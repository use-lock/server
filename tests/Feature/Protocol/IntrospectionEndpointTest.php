<?php

declare(strict_types=1);

/**
 * RFC 7662 (OAuth 2.0 Token Introspection) §2.1 (token_type_hint), §2.2 (response), §2.3 (errors); RFC 9068 §2.2 claims
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
    $this->secret = $this->client->secret;
});

/**
 * @return array{0: string, 1: AccessToken}
 */
function issueIntrospectableToken(mixed $test, ?string $clientId = null): array
{
    $minted = app(AccessTokenMinter::class)->mint(
        (string) $test->user->id,
        $clientId ?? $test->client->client_id,
        ['openid', 'email'],
        new DateInterval('PT1H'),
    );

    return [$minted->jwt, AccessToken::query()->findOrFail($minted->jti)];
}

/**
 * @param  array<string, mixed>  $parameters
 * @return TestResponse<Response>
 */
function introspect(mixed $test, array $parameters): TestResponse
{
    return $test->postJson('/oauth/introspect', [
        'client_id' => $test->client->id,
        'client_secret' => $test->secret,
        ...$parameters,
    ]);
}

it('rejects requests without client authentication', function (): void {
    $this->postJson('/oauth/introspect', ['token' => 'x'])
        ->assertUnauthorized()
        ->assertJsonPath('error', 'invalid_client')
        ->assertHeader('WWW-Authenticate', 'Basic realm="default"');
});

// RFC 7662 §2.3
it('rejects a request without a token parameter', function (): void {
    introspect($this, [])->assertStatus(400)->assertJsonPath('error', 'invalid_request');
    introspect($this, ['token' => ''])->assertStatus(400)->assertJsonPath('error', 'invalid_request');
});

// RFC 7662 §2.2 — members of an active access token, with the RFC 9068 §2.2 claims of the JWT
it('reports active for a valid access token of the same client', function (): void {
    config(['app.url' => 'https://op.test']);
    [$jwt, $token] = issueIntrospectableToken($this);
    $claims = parseAccessToken($jwt)->claims();

    introspect($this, ['token' => $jwt])->assertOk()->assertExactJson([
        'active' => true,
        'token_type' => 'Bearer',
        'client_id' => $this->client->id,
        'sub' => (string) $this->user->id,
        'scope' => 'openid email',
        'exp' => $token->expires_at?->getTimestamp(),
        'iat' => $claims->get('iat')->getTimestamp(),
        'nbf' => $claims->get('nbf')->getTimestamp(),
        'jti' => $token->id,
        'iss' => 'https://op.test',
        'aud' => ['https://op.test'],
    ]);
});

it('reports active for a token that names the caller in its audience', function (): void {
    $requester = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Requester', ['https://req.test/cb']);

    $jwt = app(AccessTokenMinter::class)->mint(
        (string) $this->user->id, $requester->client_id, ['openid'], new DateInterval('PT1H'), [(string) $this->client->id],
    )->toString();

    introspect($this, ['token' => $jwt])->assertOk()->assertJson([
        'active' => true,
        'client_id' => (string) $requester->id,
        'sub' => (string) $this->user->id,
        'aud' => [(string) $this->client->id],
    ]);
});

it('reports inactive without leaking why', function (string $case): void {
    $token = match ($case) {
        'revoked' => (function (): string {
            [$jwt, $token] = issueIntrospectableToken($this);
            $token->forceFill(['revoked_at' => now()])->save();

            return $jwt;
        })(),
        'garbage' => 'not-a-token',
        'another client' => issueIntrospectableToken(
            $this,
            app(ClientRepository::class)->createAuthorizationCodeGrantClient('Other', ['https://other.test/cb'])->client_id,
        )[0],
        'revoked refresh token' => (function (): string {
            [$value, $refreshToken] = issueRefreshToken($this);
            $refreshToken->forceFill(['revoked_at' => now()])->save();

            return $value;
        })(),
        'refresh token of another client' => issueRefreshToken(
            $this,
            (string) app(ClientRepository::class)->createAuthorizationCodeGrantClient('Other', ['https://other.test/cb'])->id,
        )[0],
        default => throw new LogicException('Unknown case.'),
    };

    introspect($this, ['token' => $token])->assertOk()->assertExactJson(['active' => false]);
})->with(['revoked', 'garbage', 'another client', 'revoked refresh token', 'refresh token of another client']);

// RFC 7662 §2.2 — a refresh token has no token_type; iss is the realm's
it('reports active for a valid refresh token of the same client', function (): void {
    config(['app.url' => 'https://op.test']);
    [$refreshTokenValue, $refreshToken] = issueRefreshToken($this);

    introspect($this, ['token' => $refreshTokenValue, 'token_type_hint' => 'refresh_token'])->assertOk()->assertExactJson([
        'active' => true,
        'scope' => 'openid',
        'client_id' => $this->client->id,
        'sub' => (string) $this->user->id,
        'exp' => $refreshToken->expires_at?->getTimestamp(),
        'iss' => 'https://op.test',
    ]);
});

// RFC 7662 §2.1 — token_type_hint only orders the lookup
it('finds the token whatever token_type_hint says', function (): void {
    [$refreshTokenValue] = issueRefreshToken($this);
    [$jwt] = issueIntrospectableToken($this);

    introspect($this, ['token' => $refreshTokenValue, 'token_type_hint' => 'access_token'])
        ->assertOk()
        ->assertJsonPath('active', true)
        ->assertJsonMissingPath('token_type');

    introspect($this, ['token' => $jwt, 'token_type_hint' => 'refresh_token'])
        ->assertOk()
        ->assertJsonPath('active', true)
        ->assertJsonPath('token_type', 'Bearer');

    introspect($this, ['token' => $refreshTokenValue, 'token_type_hint' => 'urn:example:unknown'])
        ->assertOk()
        ->assertJsonPath('active', true);
});
