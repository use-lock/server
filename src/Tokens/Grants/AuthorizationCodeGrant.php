<?php

declare(strict_types=1);

namespace Lock\Server\Tokens\Grants;

use Illuminate\Support\Facades\Date;
use Illuminate\Support\Facades\DB;
use Lock\Server\Shared\Clients\Client;
use Lock\Server\Shared\Protocol\OAuthServerException;
use Lock\Server\Shared\Protocol\Pkce;
use Lock\Server\Shared\Protocol\ResourceParameter;
use Lock\Server\Shared\Realms\RealmAudiences;
use Lock\Server\Shared\Scopes\ScopeRepository;
use Lock\Server\Shared\Tokens\Grant;
use Lock\Server\Shared\Tokens\GrantRequest;
use Lock\Server\Shared\Tokens\TokenSet;
use Lock\Server\Tokens\Events\TokenIssuanceFailed;
use Lock\Server\Tokens\Models\AuthenticationContext;
use Lock\Server\Tokens\Models\AuthorizationCode;
use Lock\Server\Tokens\TokenRevoker;

/**
 * OAuth 2.1 §4.1.3 with RFC 7636 verification. A code is single use: the
 * first redemption consumes it atomically, and any later one revokes every
 * token that descends from it (OAuth 2.1 §4.1.3, RFC 6749 §4.1.2).
 */
final readonly class AuthorizationCodeGrant implements Grant
{
    public const string TYPE = 'authorization_code';

    public function __construct(
        private InteractiveTokenIssuer $issuer,
        private ScopeRepository $scopes,
        private TokenRevoker $revoker,
        private RealmAudiences $audiences,
    ) {}

    public function type(): string
    {
        return self::TYPE;
    }

    public function handle(Client $client, GrantRequest $request): TokenSet
    {
        $code = $request->input('code');

        if (! is_string($code) || $code === '') {
            throw OAuthServerException::invalidRequest('The code parameter is missing.');
        }

        $authCode = AuthorizationCode::query()->inRealm()->where('code', $code)->first()
            ?? throw OAuthServerException::invalidGrant('The authorization code is invalid.');

        // Ownership before replay detection: only the client the code was
        // issued to can trigger the revocation of the chain it produced.
        if (! $authCode->issuedTo($client->key)) {
            throw OAuthServerException::invalidGrant('The authorization code was not issued to this client.');
        }

        if ($authCode->isRevoked()) {
            $this->replayed($authCode, $client);
        }

        if ($authCode->expires_at === null || $authCode->expires_at->isPast()) {
            throw OAuthServerException::invalidGrant('The authorization code has expired.');
        }

        $this->verifyRedirectUri($authCode, $request);
        $this->verifyCodeVerifier($authCode, $request);

        $userId = (string) $authCode->user_id;
        $audiences = $this->requestedAudiences($request, $authCode->audience ?? []);
        $scopes = $this->scopes->grant($authCode->scopes ?? [], self::TYPE, $client, $userId, $this->audiences->resolve($audiences));
        $context = $authCode->context_id !== null ? AuthenticationContext::query()->inRealm()->find($authCode->context_id) : null;

        $claims = $this->issuer->prepare($client, $userId, $scopes, self::TYPE);

        $issued = DB::transaction(function () use ($authCode, $client, $userId, $audiences, $scopes, $context, $claims): ?TokenSet {
            $consumed = AuthorizationCode::query()->whereKey($authCode->id)->whereNull('revoked_at')->update(['revoked_at' => Date::now()]) === 1;

            if (! $consumed) {
                return null;
            }

            return $this->issuer->issue(
                client: $client,
                userId: $userId,
                scopes: $scopes,
                grantType: self::TYPE,
                context: $context,
                nonce: $authCode->nonce,
                authTime: $authCode->auth_time,
                authCodeId: $authCode->id,
                withRefreshToken: $client->hasGrantType(RefreshTokenGrant::TYPE),
                audiences: $audiences,
                claims: $claims,
            );
        });

        return $issued ?? $this->replayed($authCode, $client);
    }

    /**
     * RFC 8707 §2.2: a `resource` at the token endpoint narrows the token to a
     * subset of what the authorization request asked for; it cannot add one.
     *
     * @param  list<string>  $granted
     * @return list<string>
     */
    private function requestedAudiences(GrantRequest $request, array $granted): array
    {
        $requested = ResourceParameter::parse($request->input('resource'));

        if ($requested === []) {
            return $granted;
        }

        if (array_diff($requested, $granted) !== []) {
            throw OAuthServerException::invalidTarget('The requested resource was not part of the authorization request.');
        }

        return $requested;
    }

    private function verifyRedirectUri(AuthorizationCode $authCode, GrantRequest $request): void
    {
        if ($authCode->redirect_uri === null) {
            return;
        }

        $redirectUri = $request->input('redirect_uri');

        if (! is_string($redirectUri) || $redirectUri === '') {
            throw OAuthServerException::invalidRequest('The redirect_uri parameter is required when it was part of the authorization request.');
        }

        if (! hash_equals($authCode->redirect_uri, $redirectUri)) {
            throw OAuthServerException::invalidGrant('The redirect_uri does not match the authorization request.');
        }
    }

    private function verifyCodeVerifier(AuthorizationCode $authCode, GrantRequest $request): void
    {
        $verifier = $request->input('code_verifier');

        if (! is_string($verifier) || $verifier === '') {
            throw OAuthServerException::invalidRequest('The code_verifier parameter is missing.');
        }

        if (! Pkce::isWellFormed($verifier)) {
            throw OAuthServerException::invalidRequest('The code_verifier must follow RFC 7636 §4.1.');
        }

        if ($authCode->code_challenge_method !== Pkce::METHOD) {
            throw OAuthServerException::serverError("Unsupported code challenge method [{$authCode->code_challenge_method}].");
        }

        if (! Pkce::verify($verifier, $authCode->code_challenge)) {
            throw OAuthServerException::invalidGrant('Failed to verify the code_verifier.');
        }
    }

    private function replayed(AuthorizationCode $authCode, Client $client): never
    {
        $this->revoker->revokeChain($authCode->id);

        event(new TokenIssuanceFailed(
            grantType: self::TYPE,
            reason: 'code_replayed',
            clientId: $client->clientId,
            userId: (string) $authCode->user_id,
        ));

        throw OAuthServerException::invalidGrant('The authorization code has already been used.');
    }
}
