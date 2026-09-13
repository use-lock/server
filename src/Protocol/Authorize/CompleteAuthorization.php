<?php

declare(strict_types=1);

namespace Lock\Server\Protocol\Authorize;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Lock\Server\Protocol\Events\ConsentDenied;
use Lock\Server\Shared\Clients\Clients;
use Lock\Server\Shared\Consents\ConsentStore;
use Lock\Server\Shared\Protocol\OAuthServerException;
use Lock\Server\Shared\Realms\RealmAudiences;
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

        return DB::transaction(function () use ($authorization, $resources): Response {
            $client = $this->clients->findActive($authorization->clientId)
                ?? throw OAuthServerException::invalidRequest('The client is unknown.');
            $response = $this->codes->approve($authorization, $client);

            $this->consents->grant($authorization->userId ?? throw new LogicException('An approved authorization requires a user.'), $client, $authorization->scopes, $resources);

            return $response;
        });
    }
}
