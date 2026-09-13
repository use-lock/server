<?php

declare(strict_types=1);

namespace Lock\Server\Protocol\Http\Controllers;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Lock\Server\Protocol\Authorize\AuthorizationCodeIssuer;
use Lock\Server\Protocol\Authorize\AuthorizeRequestSession;
use Lock\Server\Protocol\Authorize\AuthorizeRequestValidator;
use Lock\Server\Shared\Authentication\LoginDestination;
use Lock\Server\Shared\Authentication\PendingActions;
use Lock\Server\Shared\Clients\Client;
use Lock\Server\Shared\Clients\Clients;
use Lock\Server\Shared\Clients\FirstPartyClientConfig;
use Lock\Server\Shared\Consents\ConsentPrompt;
use Lock\Server\Shared\Consents\ConsentStore;
use Lock\Server\Shared\Consents\ConsentView;
use Lock\Server\Shared\Http\RespondsToInertiaExternalRedirects;
use Lock\Server\Shared\Protocol\AuthorizeRequest;
use Lock\Server\Shared\Protocol\OAuthServerException;
use Lock\Server\Shared\Realms\RealmAudiences;
use Lock\Server\Shared\Scopes\Scope;
use Lock\Server\Shared\Scopes\ScopeRepository;
use Lock\Server\Shared\Sessions\Sessions;
use Symfony\Component\HttpFoundation\Response;

/**
 * OAuth 2.1 §4.1.1 / OIDC Core §3.1.2: validate before touching the session.
 * Only one account exists per browser session, so `select_account` forces
 * reauthentication like `login`.
 */
class AuthorizeController
{
    use RespondsToInertiaExternalRedirects;

    public function __construct(
        protected AuthorizeRequestValidator $validator,
        protected AuthorizeRequestSession $pending,
        protected AuthorizationCodeIssuer $codes,
        protected StatefulGuard $guard,
        protected Clients $clients,
        protected ScopeRepository $scopeRepository,
        private readonly LoginDestination $loginDestination,
        private readonly FirstPartyClientConfig $firstPartyClient,
        private readonly Sessions $sessions,
        private readonly ConsentStore $consents,
        private readonly PendingActions $actions,
        private readonly RealmAudiences $audiences,
    ) {}

    public function __invoke(Request $request): Response|Responsable
    {
        $authRequest = $this->validator->validate($request);

        $intendedUrl = $this->pending->intendedUrl($request, $authRequest);

        if ($request->session()->get('oidc.login_request_url') !== $intendedUrl) {
            $request->session()->forget('oidc.prompted_for_login');
        }

        $this->pending->forget($request);

        $prompt = $this->prompt($authRequest);
        $user = $this->guard->user();

        if ($user === null) {
            return $prompt->contains('none')
                ? throw OAuthServerException::loginRequired($authRequest->redirectUri, $authRequest->state)
                : $this->promptForLogin($request, $authRequest);
        }

        // OIDC Core §3.1.2.1: the hint names the user the client expects; a
        // session belonging to somebody else must not be reused.
        if ($authRequest->idTokenHintSubject !== null && $authRequest->idTokenHintSubject !== (string) $user->getAuthIdentifier()) {
            throw OAuthServerException::loginRequired($authRequest->redirectUri, $authRequest->state);
        }

        if ($this->exceedsMaxAge($authRequest) || $prompt->contains('login') || $prompt->contains('select_account')) {
            $login = $this->reauthenticate($request, $authRequest, $prompt);

            if ($login instanceof RedirectResponse) {
                return $login;
            }
        }

        $request->session()->forget(['oidc.prompted_for_login', 'oidc.login_request_url']);

        // Existing sessions can acquire required actions through password expiry or policy changes.
        if ($this->actions->for($user) !== []) {
            if ($prompt->contains('none')) {
                throw OAuthServerException::interactionRequired($authRequest->redirectUri, $authRequest->state);
            }

            $this->pending->remember($request, $authRequest);
            $request->session()->put('url.intended', $intendedUrl);

            return redirect()->to($this->actions->url($user) ?? $this->loginDestination->url());
        }

        $authRequest->userId = (string) $user->getAuthIdentifier();

        $resources = $this->audiences->resolve($authRequest->resources);
        $scopes = $this->parseScopes($authRequest, $resources);
        $client = $this->clients->findActive($authRequest->clientId)
            ?? throw OAuthServerException::invalidRequest('The client is unknown.');

        if ($prompt->doesntContain('consent')
            && (! $client->consentRequired || $this->hasGrantedScopes($user, $client, $scopes, $resources))) {
            return $this->respondToInertia($request, $this->codes->approve($authRequest, $client));
        }

        if ($prompt->contains('none')) {
            throw OAuthServerException::consentRequired($authRequest->redirectUri, $authRequest->state);
        }

        $authToken = $this->pending->stash($request, $authRequest);

        return app(ConsentView::class)->respond(new ConsentPrompt(
            client: $client,
            user: $user,
            scopes: $scopes,
            authToken: $authToken,
            resources: $resources,
        ), $request);
    }

    /**
     * A trusted first-party client never shows consent, so its `consent`
     * prompt is dropped.
     *
     * @return Collection<int, string>
     */
    protected function prompt(AuthorizeRequest $authRequest): Collection
    {
        $prompt = collect($authRequest->prompt);

        return $this->firstPartyClient->isTrusted($authRequest->clientId)
            ? $prompt->reject(fn (string $value): bool => $value === 'consent')->values()
            : $prompt;
    }

    /**
     * A hidden scope is granted but never shown, so it neither appears on the
     * consent screen nor keeps a stored consent from covering the request.
     *
     * @param  list<string>  $resources
     * @return list<Scope>
     */
    protected function parseScopes(AuthorizeRequest $authRequest, array $resources): array
    {
        return collect($authRequest->scopes)
            ->map(fn (string $id): ?Scope => $this->scopeRepository->find($id, $resources))
            ->filter(fn (?Scope $scope): bool => $scope instanceof Scope && ! $scope->hidden)
            ->values()
            ->all();
    }

    /**
     * A trusted first-party client is consented to implicitly; anyone else
     * needs a stored consent covering every requested scope at every resource
     * the request is addressed to.
     *
     * @param  list<Scope>  $scopes
     * @param  list<string>  $resources
     */
    protected function hasGrantedScopes(Authenticatable $user, Client $client, array $scopes, array $resources): bool
    {
        if ($this->firstPartyClient->isTrusted($client->clientId)) {
            return true;
        }

        return $this->consents->covers(
            (string) $user->getAuthIdentifier(),
            $client->key,
            array_map(fn (Scope $scope): string => $scope->id, $scopes),
            $resources,
        );
    }

    protected function promptForLogin(Request $request, AuthorizeRequest $authRequest): RedirectResponse
    {
        $intendedUrl = $this->pending->intendedUrl($request, $authRequest);
        $this->pending->remember($request, $authRequest);
        $request->session()->put('oidc.prompted_for_login', true);
        $request->session()->put('oidc.login_request_url', $intendedUrl);
        $request->session()->put('url.intended', $intendedUrl);

        return redirect()->to($this->loginDestination->url());
    }

    /**
     * OIDC Core §3.1.2.1: a login older than `max_age` must be renewed; a
     * missing auth_time counts as stale.
     */
    protected function exceedsMaxAge(AuthorizeRequest $authRequest): bool
    {
        if ($authRequest->maxAge === null) {
            return false;
        }

        return time() - ($this->sessions->current()->authTime ?? 0) >= $authRequest->maxAge;
    }

    /**
     * OIDC Core §3.1.2.6: with `prompt=none` a stale login is reported as
     * `login_required` and the session is left intact. Otherwise the session
     * is torn down and the user sent to login; `oidc.prompted_for_login` marks the
     * return trip so the forced login does not loop.
     *
     * @param  Collection<int, string>  $prompt
     */
    protected function reauthenticate(Request $request, AuthorizeRequest $authRequest, Collection $prompt): ?RedirectResponse
    {
        if ($prompt->contains('none')) {
            throw OAuthServerException::loginRequired($authRequest->redirectUri, $authRequest->state);
        }

        if ($request->session()->get('oidc.prompted_for_login', false)) {
            return null;
        }

        $this->guard->logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return $this->promptForLogin($request, $authRequest);
    }
}
