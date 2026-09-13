<?php

declare(strict_types=1);

namespace Lock\Server\Tokens\Grants;

use Lock\Server\Shared\Clients\Client;
use Lock\Server\Shared\Protocol\OAuthServerException;
use Lock\Server\Shared\Protocol\ResourceParameter;
use Lock\Server\Shared\Protocol\ScopeParameter;
use Lock\Server\Shared\Realms\RealmAudiences;
use Lock\Server\Shared\Realms\RealmResolver;
use Lock\Server\Shared\Scopes\Scope;
use Lock\Server\Shared\Scopes\ScopeRepository;
use Lock\Server\Shared\Tokens\AccessTokenMinter;
use Lock\Server\Shared\Tokens\Grant;
use Lock\Server\Shared\Tokens\GrantRequest;
use Lock\Server\Shared\Tokens\TokenSet;
use Lock\Server\Tokens\Events\TokenIssuanceFailed;
use Lock\Server\Tokens\Events\TokenIssued;
use Lock\Server\Tokens\Pipeline\AccessTokenPipeline;
use Lock\Server\Tokens\Pipeline\ClientCredentialsEvent;

/**
 * OAuth 2.1 §4.2, with RFC 8707 `resource` parameters bounding the audience.
 */
final readonly class ClientCredentialsGrant implements Grant
{
    public const string TYPE = 'client_credentials';

    public function __construct(
        private AccessTokenMinter $minter,
        private AccessTokenPipeline $pipeline,
        private ScopeRepository $scopes,
        private RealmResolver $realms,
        private RealmAudiences $audiences,
    ) {}

    public function type(): string
    {
        return self::TYPE;
    }

    public function handle(Client $client, GrantRequest $request): TokenSet
    {
        $resources = ResourceParameter::parse($request->input('resource'));
        $this->assertAudiencesAllowed($client, $resources);

        $audiences = $this->audiences->resolve($resources);
        $requested = ScopeParameter::parse($request->input('scope')) ?? [];

        foreach ($requested as $scope) {
            if ($scope !== '*' && (! $this->scopes->find($scope, $audiences) instanceof Scope || ! $client->allowsScope($scope, $audiences))) {
                throw OAuthServerException::invalidScope($scope);
            }
        }

        $scopes = $this->scopes->grant($requested, self::TYPE, $client, audiences: $audiences);

        $api = $this->pipeline->run(self::TYPE, new ClientCredentialsEvent(
            client: $client,
            scopes: $scopes,
            audiences: $resources,
        ));

        if ($api->isDenied()) {
            event(new TokenIssuanceFailed(
                grantType: self::TYPE,
                reason: 'pipeline_denied',
                clientId: $client->clientId,
                denyReason: $api->denyReason(),
            ));

            throw OAuthServerException::accessDenied($api->denyReason());
        }

        $token = $this->minter->mint(
            null,
            $client->clientId,
            $scopes,
            $this->realms->current()->tokens()->clientCredentials(),
            $resources,
            $api->accessTokenClaims(),
        );

        event(new TokenIssued(
            realm: $client->realm,
            grantType: self::TYPE,
            jti: $token->jti,
            scopes: $scopes,
            clientId: $client->clientId,
            audiences: $resources,
        ));

        return new TokenSet($token);
    }

    /** @param  list<string>  $audiences */
    private function assertAudiencesAllowed(Client $client, array $audiences): void
    {
        if ($audiences !== [] && array_diff($audiences, $client->allowedAudiences) !== []) {
            throw OAuthServerException::invalidTarget('The requested resource is not permitted for this client.');
        }
    }
}
