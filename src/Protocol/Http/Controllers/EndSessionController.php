<?php

declare(strict_types=1);

namespace Lock\Server\Protocol\Http\Controllers;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Validator;
use Lock\Server\Protocol\LogoutConfirmation;
use Lock\Server\Protocol\Ui\Views\LogoutConfirmationView;
use Lock\Server\Protocol\Ui\Views\LogoutPrompt;
use Lock\Server\Shared\Authentication\IdentityGuard;
use Lock\Server\Shared\Clients\Client;
use Lock\Server\Shared\Clients\Clients;
use Lock\Server\Shared\Http\RespondsToInertiaExternalRedirects;
use Lock\Server\Shared\Protocol\OAuthServerException;
use Lock\Server\Shared\Realms\IssuerResolver;
use Lock\Server\Shared\Realms\RealmResolver;
use Lock\Server\Shared\Sessions\Sessions;
use Lock\Server\Shared\Tokens\SignedJwtParser;
use Symfony\Component\HttpFoundation\Response;

/**
 * OpenID Connect RP-Initiated Logout 1.0. The relying party is identified by
 * the verified `id_token_hint`'s `aud`, or by `client_id` when no hint is
 * given; both given, they must agree (§2). Only a relying party so identified
 * can have its registered `post_logout_redirect_uri` honoured; otherwise the
 * browser lands on the realm's logout redirect. `state` is echoed onto the
 * redirect (§3); `logout_hint` and `ui_locales` are accepted and ignored.
 *
 * The session is ended once the request proves the End-User's intent: a
 * verified hint naming the signed-in user, a same-site POST (the web group's
 * forgery check makes it one), or the confirmation token a
 * {@see LogoutConfirmationView} prompt issued (§6). A GET without such proof
 * renders the prompt; without a bound view it logs nobody out.
 */
class EndSessionController
{
    use RespondsToInertiaExternalRedirects;

    public function __construct(
        private readonly Clients $clients,
        private readonly Sessions $sessions,
        private readonly LogoutConfirmation $confirmation,
        private readonly RealmResolver $realms,
        private readonly IssuerResolver $issuer,
        private readonly SignedJwtParser $parser,
    ) {}

    public function __invoke(Request $request): Response
    {
        $hint = $this->validatedHint($request);
        $client = $this->relyingParty($request, $hint);
        $redirectUri = $this->validatedPostLogoutUri($request, $client);
        $state = $this->stringInput($request, 'state');
        $user = $this->currentUser();

        if ($request->isMethod('post') && $request->filled('logout_confirmation')) {
            $target = $user instanceof Authenticatable ? $this->confirmation->verify((string) $request->input('logout_confirmation'), $user) : null;

            if ($target === null) {
                throw OAuthServerException::invalidRequest('The logout confirmation is invalid or has expired.');
            }

            $this->logout($request);

            return $this->redirectAfterLogout($request, $target['redirect_uri'], $target['state']);
        }

        if ($request->isMethod('post') || ($hint instanceof Plain && $this->hintNamesCurrentUser($hint, $user))) {
            $this->logout($request);

            return $this->redirectAfterLogout($request, $redirectUri, $state);
        }

        if (! $user instanceof Authenticatable) {
            return $this->redirectAfterLogout($request, $redirectUri, $state);
        }

        $view = app(LogoutConfirmationView::class);

        $response = $view->respond(new LogoutPrompt(
            user: $user,
            client: $client,
            postLogoutRedirectUri: $redirectUri,
            state: $state,
            confirmationToken: $this->confirmation->issue($user, $redirectUri, $state),
        ), $request);

        return $response instanceof Responsable ? $response->toResponse($request) : $response;
    }

    private function logout(Request $request): void
    {
        $this->sessions->end($request->hasSession() ? $request->session() : null);
    }

    private function redirectAfterLogout(Request $request, ?string $redirectUri, ?string $state): Response
    {
        if ($redirectUri === null) {
            return redirect($this->realms->current()->login()->logoutRedirect);
        }

        if ($state === null) {
            return $this->respondToInertia($request, redirect()->away($redirectUri));
        }

        $separator = str_contains($redirectUri, '?') ? '&' : '?';

        return $this->respondToInertia($request, redirect()->away(
            $redirectUri.$separator.http_build_query(['state' => $state]),
        ));
    }

    private function currentUser(): ?Authenticatable
    {
        return Auth::guard(IdentityGuard::name())->user();
    }

    /** A hint is proof for the signed-in user only; a signed-out browser has nobody it could contradict. */
    private function hintNamesCurrentUser(Plain $hint, ?Authenticatable $user): bool
    {
        return ! $user instanceof Authenticatable || (string) $hint->claims()->get('sub') === (string) $user->getAuthIdentifier();
    }

    private function validatedHint(Request $request): ?Plain
    {
        $hint = $this->stringInput($request, 'id_token_hint');

        if ($hint === null) {
            return null;
        }

        $token = $this->parser->parse($hint);

        if (! $token instanceof Plain || ! (new Validator)->validate($token, new IssuedBy($this->issuer->url()))) {
            return null;
        }

        return $token;
    }

    /**
     * @throws OAuthServerException when `client_id` names a client the hint was not issued to
     */
    private function relyingParty(Request $request, ?Plain $hint): ?Client
    {
        $clientId = $this->stringInput($request, 'client_id');
        $audience = $hint instanceof Plain ? $this->audience($hint) : [];

        if ($hint instanceof Plain && $clientId !== null && ! in_array($clientId, $audience, true)) {
            throw OAuthServerException::invalidRequest('The client_id does not match the audience of the id_token_hint.');
        }

        $clientId ??= $audience[0] ?? null;

        return $clientId !== null ? $this->clients->find($clientId) : null;
    }

    private function validatedPostLogoutUri(Request $request, ?Client $client): ?string
    {
        $uri = $this->stringInput($request, 'post_logout_redirect_uri');

        if ($uri === null || ! $client instanceof Client) {
            return null;
        }

        return in_array($uri, $client->postLogoutRedirectUris, true) ? $uri : null;
    }

    /** @return list<string> */
    private function audience(Plain $hint): array
    {
        $aud = $hint->claims()->get('aud');

        return array_values(array_filter(is_array($aud) ? $aud : [$aud], is_string(...)));
    }

    private function stringInput(Request $request, string $key): ?string
    {
        $value = $request->input($key);

        return is_string($value) && $value !== '' ? $value : null;
    }
}
