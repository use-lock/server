<?php

declare(strict_types=1);

namespace Lock\Server\Tokens\Exchange;

use DateInterval;
use DateTimeImmutable;
use DateTimeInterface;
use Illuminate\Contracts\Auth\Authenticatable;
use Lcobucci\JWT\Token\Plain;
use Lock\Server\Shared\Clients\Client;
use Lock\Server\Shared\Protocol\OAuthServerException;
use Lock\Server\Shared\Realms\RealmResolver;
use Lock\Server\Shared\Scopes\ScopeRepository;
use Lock\Server\Shared\Tokens\AccessTokenMinter;
use Lock\Server\Shared\Tokens\MintedAccessToken;
use Lock\Server\Shared\Tokens\TokenExchange;
use Lock\Server\Tokens\Concerns\ResolvesTokenUser;
use Lock\Server\Tokens\Contracts\ExchangePolicy;
use Lock\Server\Tokens\Events\TokenIssuanceFailed;
use Lock\Server\Tokens\Events\TokenIssued;
use Lock\Server\Tokens\Models\AccessToken;
use Lock\Server\Tokens\Pipeline\AccessTokenPipeline;
use Lock\Server\Tokens\Pipeline\TokenExchangeEvent;
use Lock\Server\Tokens\TokenInspector;

class TokenExchanger implements TokenExchange
{
    use ResolvesTokenUser;

    private const string GRANT_URN = 'urn:ietf:params:oauth:grant-type:token-exchange';

    public function __construct(
        private readonly ExchangePolicy $policy,
        private readonly TokenInspector $inspector,
        private readonly AccessTokenMinter $minter,
        private readonly RealmResolver $realms,
        private readonly ScopeRepository $scopes,
        private readonly AccessTokenPipeline $pipeline,
    ) {}

    /**
     * @param  string[]|null  $scopes
     * @param  array<string, mixed>  $parameters
     */
    public function exchange(
        string $subjectToken,
        Client $requestingClient,
        string $audience,
        ?array $scopes = null,
        ?DateInterval $accessTokenTTL = null,
        array $parameters = [],
    ): MintedAccessToken {
        $parsed = $this->inspector->parse($subjectToken);
        $dbToken = $parsed instanceof Plain ? $this->inspector->tokenForParsed($parsed) : null;

        if (! $parsed instanceof Plain || ! $dbToken instanceof AccessToken || $dbToken->isRevoked()) {
            $this->deny($requestingClient, 'subject_token_invalid', 'The subject token is invalid.');
        }

        if (((string) ($dbToken->getAttribute('user_id') ?? '')) === '') {
            $this->deny($requestingClient, 'subject_token_userless', 'The subject token must be bound to a user.');
        }

        $claims = $parsed->claims()->all();
        $subjectExpiresAt = $this->claimTimestamp($claims['exp'] ?? null);

        if ($subjectExpiresAt <= time()) {
            $this->deny($requestingClient, 'subject_token_expired', 'The subject token has expired.');
        }

        $dbExpiresAt = $dbToken->getAttribute('expires_at');
        if ($dbExpiresAt instanceof DateTimeInterface && $dbExpiresAt->getTimestamp() <= time()) {
            $this->deny($requestingClient, 'subject_token_expired', 'The subject token has expired.');
        }

        $result = $this->policy->authorize(new ExchangeRequest(
            client: $requestingClient,
            subjectClaims: $claims,
            requestedAudience: $audience,
            requestedScopes: $scopes,
            subjectExpiresAt: $subjectExpiresAt,
            parameters: $parameters,
        ));

        $scopeIds = $this->scopes->grant($result->scopes, self::GRANT_URN, $requestingClient, $result->userId, $result->audience);

        $user = $this->resolveUser($result->userId);

        if (! $user instanceof Authenticatable) {
            $this->deny($requestingClient, 'subject_user_missing', 'The subject token user no longer exists.');
        }

        $api = $this->pipeline->run('token_exchange', new TokenExchangeEvent(
            user: $user,
            client: $requestingClient,
            scopes: $scopeIds,
            audience: $result->audience[0] ?? $requestingClient->clientId,
            subjectClaims: $claims,
        ), $result->context);

        if ($api->isDenied()) {
            event(new TokenIssuanceFailed(
                grantType: self::GRANT_URN,
                reason: 'pipeline_denied',
                clientId: $requestingClient->clientId,
                userId: $result->userId,
                denyReason: $api->denyReason(),
            ));

            throw OAuthServerException::accessDenied((string) $api->denyReason());
        }

        $ttl = $this->cappedTtl($accessTokenTTL ?? $this->realms->current()->tokens()->accessToken(), $result->expiresAt);

        $act = ['client_id' => $requestingClient->clientId];

        if (isset($claims['act']) && is_array($claims['act'])) {
            $act['act'] = $claims['act'];
        }

        $token = $this->minter->mint($result->userId, $requestingClient->clientId, $scopeIds, $ttl, $result->audience, $api->accessTokenClaims(), $act);

        event(new TokenIssued(
            realm: $requestingClient->realm,
            grantType: self::GRANT_URN,
            jti: $token->jti,
            scopes: $scopeIds,
            clientId: $requestingClient->clientId,
            userId: $result->userId,
            audiences: $result->audience,
        ));

        return $token;
    }

    private function deny(Client $requestingClient, string $reason, string $message): never
    {
        event(new TokenIssuanceFailed(grantType: self::GRANT_URN, reason: $reason, clientId: $requestingClient->clientId));

        throw OAuthServerException::invalidGrant($message);
    }

    private function cappedTtl(DateInterval $default, int $subjectExpiresAt): DateInterval
    {
        $defaultExpiry = (new DateTimeImmutable)->add($default)->getTimestamp();
        $seconds = max(1, min($defaultExpiry, $subjectExpiresAt) - time());

        return new DateInterval('PT'.$seconds.'S');
    }

    private function claimTimestamp(mixed $exp): int
    {
        if ($exp instanceof DateTimeImmutable) {
            return $exp->getTimestamp();
        }

        return is_numeric($exp) ? (int) $exp : 0;
    }
}
