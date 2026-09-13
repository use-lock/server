<?php

declare(strict_types=1);

namespace Lock\Server\Tokens;

use Carbon\CarbonInterface;
use DateTimeInterface;
use Lcobucci\JWT\Token\Plain;
use Lock\Server\Shared\Clients\Client;
use Lock\Server\Shared\Clients\Clients;
use Lock\Server\Shared\Realms\IssuerResolver;
use Lock\Server\Shared\Tokens\PresentedTokens;
use Lock\Server\Tokens\Events\TokenRevoked;
use Lock\Server\Tokens\Models\AccessToken;
use Lock\Server\Tokens\Models\RefreshToken;

/**
 * RFC 7662 §2.1 / RFC 7009 §2.1: token_type_hint is only an optimization;
 * fall back to the other type and ignore unknown hints.
 */
final readonly class PresentedTokenResolver implements PresentedTokens
{
    private const string ACCESS_TOKEN = 'access_token';

    private const string REFRESH_TOKEN = 'refresh_token';

    public function __construct(
        private TokenInspector $inspector,
        private TokenRevoker $revoker,
        private IssuerResolver $issuer,
        private Clients $clients,
    ) {}

    /** @return array<string, mixed> */
    public function introspect(Client $client, string $value, ?string $hint = null): array
    {
        $presented = $this->resolve($value, $hint);

        if (! $presented instanceof PresentedToken) {
            return $this->inactive();
        }

        return $presented->isRefreshToken()
            ? $this->introspectRefreshToken($presented, $client)
            : $this->introspectAccessToken($presented, $client);
    }

    public function revoke(Client $client, string $value, ?string $hint = null): void
    {
        $presented = $this->resolve($value, $hint);

        if (! $presented instanceof PresentedToken || ! $presented->accessToken->issuedTo($client->key)) {
            return;
        }

        $this->revoker->revoke($presented->accessToken->id);

        event(new TokenRevoked(
            realm: $presented->accessToken->realm,
            clientId: $client->clientId,
            tokenType: $presented->isRefreshToken() ? 'refresh_token' : 'access_token',
            jti: $presented->accessToken->id,
            refreshTokenJti: $presented->refreshToken?->id,
        ));
    }

    public function resolve(string $value, mixed $hint): ?PresentedToken
    {
        $order = $hint === self::REFRESH_TOKEN
            ? [self::REFRESH_TOKEN, self::ACCESS_TOKEN]
            : [self::ACCESS_TOKEN, self::REFRESH_TOKEN];

        foreach ($order as $type) {
            $presented = $type === self::ACCESS_TOKEN ? $this->accessToken($value) : $this->refreshToken($value);

            if ($presented instanceof PresentedToken) {
                return $presented;
            }
        }

        return null;
    }

    private function accessToken(string $value): ?PresentedToken
    {
        $jwt = $this->inspector->parse($value);
        $token = $jwt instanceof Plain ? $this->inspector->tokenForParsed($jwt) : null;

        return $jwt instanceof Plain && $token instanceof AccessToken ? PresentedToken::accessToken($jwt, $token) : null;
    }

    private function refreshToken(string $value): ?PresentedToken
    {
        $refreshToken = RefreshToken::query()
            ->inRealm()
            ->with('accessToken')
            ->find($value);
        $accessToken = $refreshToken?->accessToken;

        return $refreshToken instanceof RefreshToken && $accessToken instanceof AccessToken
            ? PresentedToken::refreshToken($refreshToken, $accessToken)
            : null;
    }

    /** @return array<string, mixed> RFC 7662 §2.2 and RFC 9068 §2.2 */
    private function introspectAccessToken(PresentedToken $presented, Client $client): array
    {
        $token = $presented->accessToken;
        $jwt = $presented->jwt;
        $expiresAt = $token->expires_at;

        if (! $jwt instanceof Plain
            || $token->isRevoked()
            || ($expiresAt instanceof CarbonInterface && $expiresAt->isPast())
            || (! $token->issuedTo($client->key) && ! $this->callerInAudience($client, $jwt))) {
            return $this->inactive();
        }

        $claims = $jwt->claims();

        return $this->active([
            'token_type' => 'Bearer',
            'scope' => implode(' ', $token->scopes ?? []),
            'client_id' => $this->clients->findByKey($token->client_id, $token->realm)?->clientId,
            'sub' => $this->subject($token->user_id),
            'exp' => $expiresAt?->getTimestamp(),
            'iat' => $this->timestamp($claims->get('iat')),
            'nbf' => $this->timestamp($claims->get('nbf')),
            'jti' => $token->id,
            'iss' => $this->issuer->url(),
            'aud' => $this->audience($jwt),
        ]);
    }

    /** @return array<string, mixed> */
    private function introspectRefreshToken(PresentedToken $presented, Client $client): array
    {
        $refreshToken = $presented->refreshToken;
        $accessToken = $presented->accessToken;

        if (! $refreshToken instanceof RefreshToken
            || ! $accessToken->issuedTo($client->key)
            || $refreshToken->isRevoked()
            || ! $refreshToken->expires_at instanceof CarbonInterface
            || $refreshToken->expires_at->isPast()) {
            return $this->inactive();
        }

        return $this->active([
            'scope' => implode(' ', $accessToken->scopes ?? []),
            'client_id' => $this->clients->findByKey($accessToken->client_id, $accessToken->realm)?->clientId,
            'sub' => $this->subject($accessToken->user_id),
            'exp' => $refreshToken->expires_at->getTimestamp(),
            'iss' => $this->issuer->url(),
        ]);
    }

    /**
     * @param  array<string, mixed>  $members
     * @return array<string, mixed>
     */
    private function active(array $members): array
    {
        return ['active' => true, ...array_filter($members, fn (mixed $value): bool => $value !== null)];
    }

    /** @return array<string, mixed> */
    private function inactive(): array
    {
        return ['active' => false];
    }

    private function callerInAudience(Client $client, Plain $jwt): bool
    {
        return in_array($client->clientId, $this->audience($jwt), true);
    }

    /** @return list<string> */
    private function audience(Plain $jwt): array
    {
        $aud = $jwt->claims()->get('aud');

        return array_values(array_map(strval(...), array_filter(is_array($aud) ? $aud : [$aud], is_scalar(...))));
    }

    private function timestamp(mixed $claim): ?int
    {
        if ($claim instanceof DateTimeInterface) {
            return $claim->getTimestamp();
        }

        return is_numeric($claim) ? (int) $claim : null;
    }

    private function subject(mixed $userId): ?string
    {
        if ($userId === null || $userId === '') {
            return null;
        }

        return (string) $userId;
    }
}
