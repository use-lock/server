<?php

declare(strict_types=1);

/**
 * RFC 7009 (OAuth 2.0 Token Revocation) §2.1 (request, token_type_hint), §2.2 (response, foreign tokens)
 */

use Illuminate\Testing\TestResponse;
use Lock\Server\Clients\ClientRepository;
use Lock\Server\Shared\Tokens\AccessTokenMinter;
use Lock\Server\Tokens\Models\AccessToken;
use Symfony\Component\HttpFoundation\Response;
use Workbench\App\Models\User;

beforeEach(function (): void {
    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    $this->client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/callback']);

    $minted = app(AccessTokenMinter::class)->mint((string) $this->user->id, $this->client->client_id, ['openid'], new DateInterval('PT1H'));
    $this->jwt = $minted->jwt;
    $this->token = AccessToken::query()->findOrFail($minted->jti);
});

/**
 * @param  array<string, mixed>  $parameters
 * @return TestResponse<Response>
 */
function revoke(mixed $test, array $parameters, mixed $client = null): TestResponse
{
    $client ??= $test->client;

    return $test->postJson('/oauth/revoke', [
        'client_id' => $client->id,
        'client_secret' => $client->secret,
        ...$parameters,
    ]);
}

it('revokes an access token for its own client', function (): void {
    revoke($this, ['token' => $this->jwt])->assertOk();

    expect($this->token->fresh()->isRevoked())->toBeTrue();
});

it('revokes a refresh token together with its linked access token', function (): void {
    [$refreshTokenValue, $refreshToken, $accessToken] = issueRefreshToken($this);

    revoke($this, ['token' => $refreshTokenValue, 'token_type_hint' => 'refresh_token'])->assertOk();

    expect($refreshToken->refresh()->isRevoked())->toBeTrue()
        ->and($accessToken->refresh()->isRevoked())->toBeTrue();
});

// RFC 7009 §2.1 — token_type_hint only orders the lookup
it('revokes the token whatever token_type_hint says', function (): void {
    [$refreshTokenValue, $refreshToken] = issueRefreshToken($this);

    revoke($this, ['token' => $this->jwt, 'token_type_hint' => 'refresh_token'])->assertOk();
    revoke($this, ['token' => $refreshTokenValue, 'token_type_hint' => 'urn:example:unknown'])->assertOk();

    expect($this->token->fresh()->isRevoked())->toBeTrue()
        ->and($refreshToken->refresh()->isRevoked())->toBeTrue();
});

// RFC 7009 §2.2 — tokens of other clients and unknown tokens are silently ignored
it('answers 200 without revoking for tokens of other clients or unknown tokens', function (): void {
    $other = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Other', ['https://other.test/cb']);
    [$refreshTokenValue, $refreshToken, $accessToken] = issueRefreshToken($this);

    revoke($this, ['token' => $this->jwt], $other)->assertOk();
    revoke($this, ['token' => $refreshTokenValue, 'token_type_hint' => 'refresh_token'], $other)->assertOk();
    revoke($this, ['token' => 'not-a-token'])->assertOk();

    expect($this->token->fresh()->isRevoked())->toBeFalse()
        ->and($refreshToken->refresh()->isRevoked())->toBeFalse()
        ->and($accessToken->refresh()->isRevoked())->toBeFalse();
});

// RFC 7009 §2.2.1
it('rejects a revocation request without a token parameter', function (): void {
    revoke($this, [])->assertStatus(400)->assertJsonPath('error', 'invalid_request');

    expect($this->token->fresh()->isRevoked())->toBeFalse();
});

it('rejects unauthenticated revocation', function (): void {
    $this->postJson('/oauth/revoke', ['token' => $this->jwt])
        ->assertUnauthorized()
        ->assertJsonPath('error', 'invalid_client')
        ->assertHeader('WWW-Authenticate', 'Basic realm="default"');

    expect($this->token->fresh()->isRevoked())->toBeFalse();
});

it('lets a public client revoke its own refresh token', function (): void {
    $public = app(ClientRepository::class)->createAuthorizationCodeGrantClient('SPA', ['https://spa.test/cb'], confidential: false);
    [$refreshTokenValue, $refreshToken, $accessToken] = issueRefreshToken($this, (string) $public->id);

    $this->postJson('/oauth/revoke', [
        'client_id' => $public->client_id,
        'token' => $refreshTokenValue,
        'token_type_hint' => 'refresh_token',
    ])->assertOk();

    expect($refreshToken->refresh()->isRevoked())->toBeTrue()
        ->and($accessToken->refresh()->isRevoked())->toBeTrue();
});
