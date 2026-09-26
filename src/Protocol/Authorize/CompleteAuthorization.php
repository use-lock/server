<?php

declare(strict_types=1);

namespace Lock\Server\Protocol\Authorize;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Lock\Server\Protocol\Events\ConsentDenied;
use Lock\Server\Shared\Clients\Client;
use Lock\Server\Shared\Clients\Clients;
use Lock\Server\Shared\Consents\ConsentPrompt;
use Lock\Server\Shared\Consents\ConsentStore;
use Lock\Server\Shared\Protocol\AuthorizeRequest;
use Lock\Server\Shared\Protocol\OAuthServerException;
use Lock\Server\Shared\Realms\RealmAudiences;
use Lock\Server\Shared\Scopes\Scope;
use Lock\Server\Shared\Scopes\ScopeRepository;
use Lock\Server\Shared\Scopes\ScopeTemplate;
use LogicException;
use Symfony\Component\HttpFoundation\Response;

readonly class CompleteAuthorization
{
    public function __construct(
        protected AuthorizeRequestSession $session,
        protected AuthorizationCodeIssuer $codes,
        protected RealmAudiences $audiences,
        protected ConsentStore $consents,
        protected Clients $clients,
        protected ScopeRepository $scopes,
    ) {}

    public function __invoke(Request $request, bool $approved): Response
    {
        $authorization = $this->session->pull($request);
        $resources = $this->audiences->resolve($authorization->resources);

        if (! $approved) {
            $response = $this->codes->deny($authorization);
            event(new ConsentDenied($authorization->scopes, $resources, $authorization->userId, $authorization->clientId));

            return $response;
        }

        return DB::transaction(function () use ($request, $authorization, $resources): Response {
            $client = $this->clients->findActive($authorization->clientId)
                ?? throw OAuthServerException::invalidRequest('The client is unknown.');
            $authorization = $authorization->withScopes($this->approvedScopes($request, $authorization, $client, $resources));
            $response = $this->codes->approve($authorization, $client);

            $this->consents->grant($authorization->userId ?? throw new LogicException('An approved authorization requires a user.'), $client, $authorization->scopes, $resources);

            return $response;
        });
    }

    /**
     * RFC 6749 §3.3 lets the authorization server grant fewer scopes than
     * requested. A posted `scopes` selection keeps the requested scopes the
     * user left checked and fills each open template with the chosen values;
     * hidden scopes were never shown, so they stay. Without a selection every
     * requested scope stays. An open template is also filled with the value
     * picked in its consent field and lapses when there is none. Either way the result is
     * finalized as for the token, so no consent is stored for a value the
     * user may not have.
     *
     * @param  list<string>  $resources
     * @return list<string>
     */
    protected function approvedScopes(Request $request, AuthorizeRequest $authorization, Client $client, array $resources): array
    {
        $selection = $request->input('scopes');
        $selected = is_array($selection) ? array_values(array_filter($selection, is_string(...))) : null;
        $approved = [];
        $openTemplates = 0;

        foreach ($authorization->scopes as $id) {
            $scope = $this->scopes->find($id, $resources);

            if ($scope instanceof Scope && $scope->isOpen()) {
                $template = (string) $scope->template;
                $chosen = $scope->hidden ? null : $request->input(ConsentPrompt::parameterField($openTemplates++));
                array_push($approved, ...array_filter($selected ?? [], fn (string $value): bool => ScopeTemplate::match($template, $value) !== null));

                if (is_string($chosen) && $chosen !== '') {
                    $approved[] = ScopeTemplate::fill($template, $chosen);
                }
            } elseif ($selected === null || ($scope instanceof Scope && $scope->hidden) || in_array($id, $selected, true)) {
                $approved[] = $id;
            }
        }

        return $this->scopes->grant(array_values(array_unique($approved)), 'authorization_code', $client, $authorization->userId, $resources);
    }
}
