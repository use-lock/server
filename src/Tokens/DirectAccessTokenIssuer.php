<?php

declare(strict_types=1);

namespace Lock\Server\Tokens;

use Illuminate\Support\Facades\DB;
use Lock\Server\Shared\Authentication\RealmUser;
use Lock\Server\Shared\Clients\Client;
use Lock\Server\Shared\Clients\Clients;
use Lock\Server\Shared\Realms\RealmResolver;
use Lock\Server\Shared\Scopes\ScopeRepository;
use Lock\Server\Shared\Tokens\AccessTokenMinter;
use Lock\Server\Tokens\Events\TokenIssuanceFailed;
use Lock\Server\Tokens\Events\TokenIssued;
use Lock\Server\Tokens\Exceptions\TokenIssuanceDeniedException;
use Lock\Server\Tokens\Models\AccessToken;
use Lock\Server\Tokens\Pipeline\AccessTokenPipeline;
use Lock\Server\Tokens\Pipeline\DirectAccessTokenEvent;

final readonly class DirectAccessTokenIssuer
{
    public const string GRANT_TYPE = 'direct_access';

    public function __construct(
        private Clients $clients,
        private ScopeRepository $scopes,
        private AccessTokenMinter $minter,
        private AccessTokenPipeline $pipeline,
        private RealmResolver $realms,
    ) {}

    /**
     * @param  list<string>  $scopes
     * @param  array<string, mixed>  $context
     */
    public function issue(RealmUser $user, Client $client, string $name, array $scopes = [], array $context = []): DirectAccessTokenResult
    {
        $client = $this->resolveClient($client, $user);
        $userId = (string) $user->getAuthIdentifier();

        $granted = $this->scopes->grant($scopes, self::GRANT_TYPE, $client, $userId);

        $claims = $this->runTriggers($user, $client, $granted, $context);

        return DB::transaction(function () use ($client, $userId, $granted, $claims, $name, $context): DirectAccessTokenResult {
            $token = $this->minter->mint(
                userId: $userId,
                clientId: $client->clientId,
                scopeIds: $granted,
                ttl: $this->realms->current()->tokens()->accessToken(),
                extraClaims: $claims,
            );

            $record = AccessToken::query()->inRealm()->findOrFail($token->jti);
            $record->update([
                'name' => $name,
                'context' => $context === [] ? null : $context,
            ]);

            event(new TokenIssued(
                realm: $client->realm,
                grantType: self::GRANT_TYPE,
                jti: $token->jti,
                scopes: $granted,
                clientId: $client->clientId,
                userId: $userId,
            ));

            return new DirectAccessTokenResult(
                accessToken: $token->jwt,
                token: $record,
            );
        });
    }

    private function resolveClient(Client $client, RealmUser $user): Client
    {
        $registered = $client->realm === $this->realms->current()->identifier()
            ? $this->clients->findByKey($client->key)
            : null;

        if (! $registered instanceof Client || $registered->revoked || ! $registered->hasGrantType(self::GRANT_TYPE)) {
            event(new TokenIssuanceFailed(
                grantType: self::GRANT_TYPE,
                reason: 'client_ineligible',
                clientId: $client->clientId,
                userId: (string) $user->getAuthIdentifier(),
            ));

            throw new TokenIssuanceDeniedException('client_ineligible');
        }

        return $registered;
    }

    /**
     * @param  list<string>  $granted
     * @param  array<string, mixed>  $context
     * @return array<string, mixed>
     */
    private function runTriggers(RealmUser $user, Client $client, array $granted, array $context): array
    {
        if (! $this->pipeline->has('direct_access')) {
            return [];
        }

        $api = $this->pipeline->run('direct_access', new DirectAccessTokenEvent(
            user: $user,
            client: $client,
            scopes: $granted,
            context: $context,
        ));

        if ($api->isDenied()) {
            event(new TokenIssuanceFailed(
                grantType: self::GRANT_TYPE,
                reason: 'pipeline_denied',
                clientId: $client->clientId,
                userId: (string) $user->getAuthIdentifier(),
                denyReason: $api->denyReason(),
            ));

            throw new TokenIssuanceDeniedException((string) $api->denyReason());
        }

        return $api->accessTokenClaims();
    }
}
