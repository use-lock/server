<?php

declare(strict_types=1);

namespace Lock\Server\Tokens\Grants;

use DateTimeImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Lock\Server\Shared\Clients\Client;
use Lock\Server\Shared\Protocol\OAuthServerException;
use Lock\Server\Shared\Realms\RealmResolver;
use Lock\Server\Shared\Tokens\AccessTokenMinter;
use Lock\Server\Shared\Tokens\MintedAccessToken;
use Lock\Server\Shared\Tokens\TokenSet;
use Lock\Server\Tokens\Concerns\ResolvesTokenUser;
use Lock\Server\Tokens\Events\TokenIssuanceFailed;
use Lock\Server\Tokens\Events\TokenIssued;
use Lock\Server\Tokens\IdTokenBuilder;
use Lock\Server\Tokens\IdTokenRequest;
use Lock\Server\Tokens\Models\AccessToken;
use Lock\Server\Tokens\Models\AuthenticationContext;
use Lock\Server\Tokens\Models\RefreshToken;
use Lock\Server\Tokens\Pipeline\AccessTokenApi;
use Lock\Server\Tokens\Pipeline\AccessTokenPipeline;
use Lock\Server\Tokens\Pipeline\AuthorizationCodeEvent;

/**
 * Authorization-code triggers run before persistence so denial stops issuance.
 * Their claims override the context's potentially stale login-time claims.
 */
final readonly class InteractiveTokenIssuer
{
    use ResolvesTokenUser;

    public function __construct(
        private AccessTokenMinter $minter,
        private AccessTokenPipeline $pipeline,
        private IdTokenBuilder $idTokens,
        private RealmResolver $realms,
    ) {}

    /**
     * @param  array<string, mixed>  $claims
     * @param  list<string>  $scopes
     * @param  string|null  $authCodeId  the code this token descends from, so a replayed code or refresh token can revoke the whole chain
     * @param  list<string>  $audiences  RFC 8707 resources the token is for; empty for the realm default
     */
    public function issue(
        Client $client,
        string $userId,
        array $scopes,
        string $grantType,
        ?AuthenticationContext $context,
        ?string $nonce,
        ?int $authTime,
        ?string $authCodeId,
        bool $withRefreshToken,
        array $audiences = [],
        array $claims = [],
    ): TokenSet {
        $tokens = $this->realms->current()->tokens();

        $accessToken = $this->minter->mint(
            $userId,
            $client->clientId,
            $scopes,
            $tokens->accessToken(),
            audiences: $audiences,
            extraClaims: [...($context instanceof AuthenticationContext ? $context->access_token_claims : []), ...$claims],
        );

        if ($context instanceof AuthenticationContext || $authCodeId !== null) {
            AccessToken::query()->whereKey($accessToken->jti)->update([
                'auth_code_id' => $authCodeId,
                'context_id' => $context?->id,
            ]);
        }

        $refreshToken = $withRefreshToken ? $this->issueRefreshToken($accessToken) : null;

        $idToken = in_array('openid', $scopes, true)
            ? $this->idTokens->build(new IdTokenRequest(
                userId: $userId,
                clientId: $client->clientId,
                scopes: $scopes,
                accessToken: $accessToken->jwt,
                nonce: $nonce,
                authTime: $authTime,
                amr: $context instanceof AuthenticationContext ? $context->amr : [],
                idTokenClaims: $context instanceof AuthenticationContext ? $context->id_token_claims : [],
                sid: $context?->session_id,
            ))
            : null;

        event(new TokenIssued(
            realm: $client->realm,
            grantType: $grantType,
            jti: $accessToken->jti,
            scopes: $scopes,
            clientId: $client->clientId,
            userId: $userId,
            sid: $context?->session_id,
            audiences: $audiences,
        ));

        return new TokenSet($accessToken, $refreshToken, $idToken);
    }

    /**
     * @param  list<string>  $scopes
     * @return array<string, mixed>
     */
    public function prepare(Client $client, string $userId, array $scopes, string $grantType): array
    {
        $api = $this->runTriggers($client, $userId, $scopes, $grantType);

        if ($api?->isDenied() === true) {
            event(new TokenIssuanceFailed(
                grantType: $grantType,
                reason: 'pipeline_denied',
                clientId: $client->clientId,
                userId: $userId,
                denyReason: $api->denyReason(),
            ));

            throw OAuthServerException::accessDenied($api->denyReason());
        }

        return $api?->accessTokenClaims() ?? [];
    }

    /**
     * @param  list<string>  $scopes
     */
    private function runTriggers(Client $client, string $userId, array $scopes, string $grantType): ?AccessTokenApi
    {
        if (! $this->pipeline->has('authorization_code')) {
            return null;
        }

        $user = $this->resolveUser($userId);

        if (! $user instanceof Authenticatable) {
            return null;
        }

        return $this->pipeline->run('authorization_code', new AuthorizationCodeEvent(
            user: $user,
            client: $client,
            scopes: $scopes,
            grantType: $grantType,
        ));
    }

    private function issueRefreshToken(MintedAccessToken $accessToken): string
    {
        $id = bin2hex(random_bytes(40));

        RefreshToken::query()->forceCreate([
            'realm' => $this->realms->current()->identifier(),
            'id' => $id,
            'access_token_id' => $accessToken->jti,
            'expires_at' => (new DateTimeImmutable)->add($this->realms->current()->tokens()->refreshToken()),
        ]);

        return $id;
    }
}
