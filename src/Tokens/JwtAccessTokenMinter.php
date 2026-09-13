<?php

declare(strict_types=1);

namespace Lock\Server\Tokens;

use DateInterval;
use DateTimeImmutable;
use Lock\Server\Shared\Clients\Clients;
use Lock\Server\Shared\Protocol\ProtocolClaims;
use Lock\Server\Shared\Realms\IssuerResolver;
use Lock\Server\Shared\Realms\RealmAudiences;
use Lock\Server\Shared\SigningKeys\Keyring;
use Lock\Server\Shared\Tokens\AccessTokenMinter;
use Lock\Server\Shared\Tokens\MintedAccessToken;
use Lock\Server\Tokens\Models\AccessToken;
use RuntimeException;

/**
 * RFC 9068: `aud` defaults to the realm issuer (§3); RFC 8707 `resource`
 * and token-exchange `audience` override it. Keep `scopes` alongside `scope`
 * for consumers that read the array.
 */
final readonly class JwtAccessTokenMinter implements AccessTokenMinter
{
    public function __construct(
        private Clients $clients,
        private Keyring $keyring,
        private IssuerResolver $issuer,
        private RealmAudiences $audiences,
    ) {}

    public function mint(
        ?string $userId,
        string $clientId,
        array $scopeIds,
        DateInterval $ttl,
        array $audiences = [],
        array $extraClaims = [],
        ?array $actor = null,
    ): MintedAccessToken {
        $client = $this->clients->findActive($clientId)
            ?? throw new RuntimeException("Cannot mint an access token for the unknown or revoked client [{$clientId}].");

        $jti = bin2hex(random_bytes(40));
        $now = new DateTimeImmutable;
        $expiresAt = $now->add($ttl);
        $audience = $audiences !== [] ? $audiences : $this->audiences->default();

        $builder = $this->keyring->builder()
            ->withHeader('typ', 'at+jwt')
            ->issuedBy($this->issuer->url())
            ->identifiedBy($jti)
            ->issuedAt($now)
            ->canOnlyBeUsedAfter($now)
            ->expiresAt($expiresAt)
            ->relatedTo($userId ?? $client->clientId)
            ->permittedFor(...$audience)
            ->withClaim('client_id', $client->clientId)
            ->withClaim('scope', implode(' ', $scopeIds))
            ->withClaim('scopes', $scopeIds);

        foreach ($extraClaims as $name => $value) {
            if (! ProtocolClaims::isAccessTokenReserved((string) $name)) {
                $builder = $builder->withClaim((string) $name, $value);
            }
        }

        if ($actor !== null) {
            $builder = $builder->withClaim('act', $actor);
        }

        $jwt = $this->keyring->sign($builder);

        AccessToken::query()->forceCreate([
            'realm' => AccessToken::currentRealm(),
            'id' => $jti,
            'user_id' => $userId,
            'client_id' => $client->key,
            'scopes' => $scopeIds,
            'audience' => $audience,
            'expires_at' => $expiresAt,
        ]);

        return new MintedAccessToken(
            jwt: $jwt,
            jti: $jti,
            userId: $userId,
            clientId: $client->clientId,
            scopes: $scopeIds,
            audience: $audience,
            issuedAt: $now,
            expiresAt: $expiresAt,
        );
    }
}
