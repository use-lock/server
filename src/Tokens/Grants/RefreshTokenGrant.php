<?php

declare(strict_types=1);

namespace Lock\Server\Tokens\Grants;

use Illuminate\Support\Facades\DB;
use Lock\Server\Shared\Clients\Client;
use Lock\Server\Shared\Protocol\ClientAuthenticationFailed;
use Lock\Server\Shared\Protocol\OAuthServerException;
use Lock\Server\Shared\Protocol\ResourceParameter;
use Lock\Server\Shared\Protocol\ScopeParameter;
use Lock\Server\Shared\Realms\RealmAudiences;
use Lock\Server\Shared\Scopes\ScopeRepository;
use Lock\Server\Shared\Sessions\Sessions;
use Lock\Server\Shared\Sessions\SessionSnapshot;
use Lock\Server\Shared\Tokens\Grant;
use Lock\Server\Shared\Tokens\GrantRequest;
use Lock\Server\Shared\Tokens\TokenSet;
use Lock\Server\Tokens\Events\TokenIssuanceFailed;
use Lock\Server\Tokens\Models\AccessToken;
use Lock\Server\Tokens\Models\AuthenticationContext;
use Lock\Server\Tokens\Models\RefreshToken;
use Lock\Server\Tokens\TokenRevoker;

/**
 * OAuth 2.1 §4.3. Refresh tokens rotate: each use revokes the presented token
 * and the access token it belongs to. A refresh is denied once the
 * authentication context it descends from has expired or its session ended,
 * so no token outlives the login that produced it.
 */
final readonly class RefreshTokenGrant implements Grant
{
    public const string TYPE = 'refresh_token';

    public function __construct(
        private InteractiveTokenIssuer $issuer,
        private ScopeRepository $scopes,
        private Sessions $sessions,
        private TokenRevoker $revoker,
        private RealmAudiences $audiences,
    ) {}

    public function type(): string
    {
        return self::TYPE;
    }

    public function handle(Client $client, GrantRequest $request): TokenSet
    {
        $value = $request->input('refresh_token');

        if (! is_string($value) || $value === '') {
            throw OAuthServerException::invalidRequest('The refresh_token parameter is missing.');
        }

        $refreshToken = RefreshToken::query()
            ->inRealm()
            ->with('accessToken')
            ->find($value);
        $accessToken = $refreshToken?->accessToken;

        if ($refreshToken === null || $accessToken === null) {
            throw OAuthServerException::invalidGrant('The refresh token is invalid.');
        }

        if (! $accessToken->issuedTo($client->key)) {
            event(new ClientAuthenticationFailed($request->endpoint, 'refresh_token_client_mismatch', $client->clientId));

            throw OAuthServerException::invalidGrant('The refresh token was not issued to this client.');
        }

        if ($refreshToken->isRevoked()) {
            $this->replayed($accessToken);
        }

        if ($refreshToken->expires_at === null || $refreshToken->expires_at->isPast()) {
            throw OAuthServerException::invalidGrant('The refresh token has expired.');
        }

        $userId = $accessToken->user_id;

        if ($userId === null || $userId === '') {
            throw OAuthServerException::invalidGrant('The refresh token is not bound to a user.');
        }

        $original = array_values($accessToken->scopes ?? []);
        $requested = ScopeParameter::parse($request->input('scope')) ?? $original;

        // OAuth 2.1 §4.3.1: the refreshed token may carry the original scopes or fewer.
        foreach ($requested as $scope) {
            if (! in_array($scope, $original, true)) {
                event(new TokenIssuanceFailed(
                    grantType: self::TYPE,
                    reason: 'scope_escalation',
                    clientId: $client->clientId,
                    scope: $scope,
                ));

                throw OAuthServerException::invalidScope($scope);
            }
        }

        $audiences = $this->requestedAudiences($request, $accessToken->audience ?? []);
        $scopes = $this->scopes->grant($requested, self::TYPE, $client, (string) $userId, $this->audiences->resolve($audiences));
        $context = $this->activeContext($accessToken);

        $claims = $this->issuer->prepare($client, (string) $userId, $scopes, self::TYPE);

        $issued = DB::transaction(function () use ($refreshToken, $accessToken, $client, $userId, $scopes, $context, $audiences, $claims): ?TokenSet {
            $consumed = RefreshToken::query()->whereKey($refreshToken->id)->whereNull('revoked_at')->update(['revoked_at' => now()]) === 1;

            if (! $consumed) {
                return null;
            }

            $this->revoker->revoke($accessToken->id);

            return $this->issuer->issue(
                client: $client,
                userId: (string) $userId,
                scopes: $scopes,
                grantType: self::TYPE,
                context: $context,
                nonce: null,
                authTime: $context?->auth_time,
                authCodeId: $accessToken->auth_code_id,
                withRefreshToken: true,
                audiences: $audiences,
                claims: $claims,
            );
        });

        return $issued ?? $this->replayed($accessToken);
    }

    /**
     * RFC 8707 §2.2: the refreshed token keeps the audience of the one it
     * replaces unless a `resource` narrows it to a subset.
     *
     * @param  list<string>  $current
     * @return list<string>
     */
    private function requestedAudiences(GrantRequest $request, array $current): array
    {
        $requested = ResourceParameter::parse($request->input('resource'));

        if ($requested === []) {
            return $current;
        }

        if (array_diff($requested, $current) !== []) {
            throw OAuthServerException::invalidTarget('The requested resource is not among the audiences of the refresh token.');
        }

        return $requested;
    }

    /**
     * Null when the token never carried a context (a non-interactive chain);
     * otherwise the context must still be alive.
     */
    private function activeContext(AccessToken $accessToken): ?AuthenticationContext
    {
        $contextId = $accessToken->context_id;

        if ($contextId === null) {
            return null;
        }

        $context = AuthenticationContext::query()->inRealm()->find($contextId)
            ?? $this->deny('context_expired', 'The authentication session has expired; re-authentication is required.');

        if ($context->session_id !== null) {
            $session = $this->sessions->get($context->session_id);

            if (! $session instanceof SessionSnapshot || ! $session->active) {
                $this->deny('session_ended', 'The authentication session has ended; re-authentication is required.', $context->session_id);
            }
        } elseif ($context->expires_at !== null && $context->expires_at->isPast()) {
            $this->deny('context_expired', 'The authentication session has expired; re-authentication is required.');
        }

        return $context;
    }

    private function replayed(AccessToken $accessToken): never
    {
        if ($accessToken->auth_code_id !== null) {
            $this->revoker->revokeChain($accessToken->auth_code_id);
        }

        $this->deny('refresh_token_reused', 'The refresh token has been revoked.');
    }

    private function deny(string $reason, string $message, ?string $sid = null): never
    {
        event(new TokenIssuanceFailed(grantType: self::TYPE, reason: $reason, sid: $sid));

        throw OAuthServerException::invalidGrant($message);
    }
}
