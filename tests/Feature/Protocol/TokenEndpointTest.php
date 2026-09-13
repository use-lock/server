<?php

declare(strict_types=1);

/**
 * RFC 6749 §2.3.1 (client authentication), §3.2 / §5.1 / §5.2 (token endpoint, responses, errors);
 * OAuth 2.1 §1.5 (no password grant), §4.1.3 (code redemption, replay); RFC 7636 §4.6
 */

use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Foundation\Http\Middleware\ValidateCsrfToken;
use Lock\Server\Clients\ClientRepository;
use Lock\Server\Shared\Clients\TokenEndpointAuthMethod;
use Lock\Server\Support\Testing\InteractsWithOidc;
use Lock\Server\Support\Testing\PkcePair;
use Lock\Server\Tests\FeatureTestCase;
use Lock\Server\Tokens\Models\AccessToken;
use Lock\Server\Tokens\Models\AuthorizationCode;
use Lock\Server\Tokens\Models\RefreshToken;
use Workbench\App\Models\User;

uses(InteractsWithOidc::class);

beforeEach(function (): void {
    $this->withoutMiddleware([ValidateCsrfToken::class, PreventRequestForgery::class]);
    fakeConsentViewUsing(fn (array $parameters) => response()->json(['authToken' => $parameters['authToken']]));

    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'email_verified_at' => now(), 'password' => 'x']);
    $this->client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/callback']);
});

function obtainAuthorizationCode(FeatureTestCase $test, PkcePair $pkce): string
{
    $view = $test->actingAsIdentity($test->user, authTime: time() - 60)
        ->get('/oauth/authorize?'.http_build_query([
            'client_id' => $test->client->id,
            'redirect_uri' => 'https://rp.test/callback',
            'response_type' => 'code',
            'scope' => 'openid email',
            'state' => 'st4te',
            'code_challenge' => $pkce->challenge,
            'code_challenge_method' => 'S256',
        ]))
        ->assertOk();

    $approve = $test->post('/oauth/authorize/consent', ['auth_token' => $view->json('authToken')])->assertRedirect();
    parse_str((string) parse_url((string) $approve->headers->get('Location'), PHP_URL_QUERY), $params);

    return $params['code'];
}

/**
 * @param  array<string, mixed>  $overrides
 * @return array<string, mixed>
 */
function codeRedemption(FeatureTestCase $test, string $code, PkcePair $pkce, array $overrides = []): array
{
    return array_merge([
        'grant_type' => 'authorization_code',
        'client_id' => $test->client->id,
        'client_secret' => $test->client->secret,
        'redirect_uri' => 'https://rp.test/callback',
        'code' => $code,
        'code_verifier' => $pkce->verifier,
    ], $overrides);
}

// RFC 6749 §5.2 / OAuth 2.1 §1.5
it('rejects a missing, unknown or removed grant_type before authenticating the client', function (?string $grantType, string $error): void {
    $this->post('/oauth/token', array_filter(['grant_type' => $grantType]))
        ->assertStatus(400)
        ->assertJsonPath('error', $error);
})->with([
    'missing' => [null, 'invalid_request'],
    'unknown' => ['urn:example:nope', 'unsupported_grant_type'],
    'password grant' => ['password', 'unsupported_grant_type'],
]);

// RFC 6749 §2.3.1 (client_secret_basic)
it('authenticates a client through HTTP Basic credentials and forbids caching the response', function (): void {
    $client = app(ClientRepository::class)->createClientCredentialsGrantClient('M2M');
    $client->forceFill(['token_endpoint_auth_method' => TokenEndpointAuthMethod::ClientSecretBasic])->save();

    $response = $this->withBasicAuth($client->client_id, (string) $client->secret)
        ->post('/oauth/token', ['grant_type' => 'client_credentials'])
        ->assertOk();

    expect($response->json('token_type'))->toBe('Bearer')
        ->and($response->headers->get('Cache-Control'))->toContain('no-store')
        ->and($response->headers->get('Pragma'))->toBe('no-cache');
});

// RFC 6749 §2.3.1 — one authentication method per request, and the registered one
it('rejects a client that presents its secret through both Basic and body credentials', function (): void {
    $client = app(ClientRepository::class)->createClientCredentialsGrantClient('M2M');

    $this->withBasicAuth($client->client_id, (string) $client->secret)
        ->post('/oauth/token', [
            'grant_type' => 'client_credentials',
            'client_secret' => $client->secret,
        ])->assertStatus(400)->assertJsonPath('error', 'invalid_request');
});

it('rejects a client that authenticates with a method it is not registered for', function (): void {
    $client = app(ClientRepository::class)->createClientCredentialsGrantClient('M2M');

    $this->withBasicAuth($client->client_id, (string) $client->secret)
        ->post('/oauth/token', ['grant_type' => 'client_credentials'])
        ->assertStatus(401)
        ->assertJsonPath('error', 'invalid_client');
});

it('rejects missing or wrong client credentials with a Basic challenge', function (): void {
    $client = app(ClientRepository::class)->createClientCredentialsGrantClient('M2M');

    $this->post('/oauth/token', ['grant_type' => 'client_credentials'])
        ->assertStatus(401)
        ->assertJsonPath('error', 'invalid_client');

    $this->post('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $client->client_id,
        'client_secret' => 'wrong',
    ])->assertStatus(401)
        ->assertJsonPath('error', 'invalid_client')
        ->assertHeader('WWW-Authenticate', 'Basic realm="default"');
});

it('rejects a public client that presents a secret', function (): void {
    $public = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Public', ['https://p.test/cb'], confidential: false);

    $this->post('/oauth/token', [
        'grant_type' => 'refresh_token',
        'client_id' => $public->client_id,
        'client_secret' => 'unexpected',
        'refresh_token' => 'x',
    ])->assertStatus(401)->assertJsonPath('error', 'invalid_client');
});

// RFC 6749 §5.2 (unauthorized_client)
it('rejects a client that is not registered for the grant', function (): void {
    $this->post('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $this->client->id,
        'client_secret' => $this->client->secret,
    ])->assertStatus(400)->assertJsonPath('error', 'unauthorized_client');
});

// OAuth 2.1 §4.1.3 — a replayed code revokes everything it produced
it('rejects a replayed code and revokes the tokens it produced', function (): void {
    $pkce = $this->pkce();
    $code = obtainAuthorizationCode($this, $pkce);

    $first = $this->post('/oauth/token', codeRedemption($this, $code, $pkce))->assertOk();

    $this->post('/oauth/token', codeRedemption($this, $code, $pkce))
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_grant');

    $accessToken = parseAccessToken((string) $first->json('access_token'));

    expect(AccessToken::query()->find($accessToken->claims()->get('jti'))->isRevoked())->toBeTrue()
        ->and(RefreshToken::query()->find($first->json('refresh_token'))->isRevoked())->toBeTrue();

    $this->post('/oauth/token', [
        'grant_type' => 'refresh_token',
        'client_id' => $this->client->id,
        'client_secret' => $this->client->secret,
        'refresh_token' => $first->json('refresh_token'),
    ])->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
});

it('rejects a code presented by another client and leaves it usable for its rightful client', function (): void {
    $pkce = $this->pkce();
    $code = obtainAuthorizationCode($this, $pkce);
    $other = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Other', ['https://rp.test/callback']);

    $this->post('/oauth/token', codeRedemption($this, $code, $pkce, [
        'client_id' => $other->id,
        'client_secret' => $other->secret,
    ]))->assertStatus(400)->assertJsonPath('error', 'invalid_grant');

    $first = $this->post('/oauth/token', codeRedemption($this, $code, $pkce))->assertOk();

    $this->post('/oauth/token', codeRedemption($this, $code, $pkce, [
        'client_id' => $other->id,
        'client_secret' => $other->secret,
    ]))->assertStatus(400)->assertJsonPath('error', 'invalid_grant');

    $accessToken = parseAccessToken((string) $first->json('access_token'));

    expect(AccessToken::query()->find($accessToken->claims()->get('jti'))->isRevoked())->toBeFalse()
        ->and(RefreshToken::query()->find($first->json('refresh_token'))->isRevoked())->toBeFalse();
});

it('rejects an expired authorization code', function (): void {
    $pkce = $this->pkce();
    $code = obtainAuthorizationCode($this, $pkce);
    AuthorizationCode::query()->where('code', $code)->update(['expires_at' => now()->subMinute()]);

    $this->post('/oauth/token', codeRedemption($this, $code, $pkce))
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_grant');
});

// RFC 6749 §4.1.3 — redirect_uri must be repeated and must match
it('requires the redirect_uri the authorization request carried', function (): void {
    $pkce = $this->pkce();
    $code = obtainAuthorizationCode($this, $pkce);

    $this->post('/oauth/token', codeRedemption($this, $code, $pkce, ['redirect_uri' => null]))
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_request');

    $this->post('/oauth/token', codeRedemption($this, $code, $pkce, ['redirect_uri' => 'https://rp.test/other']))
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_grant');
});

// RFC 7636 §4.6
it('requires a well-formed code_verifier that matches the challenge', function (): void {
    $pkce = $this->pkce();
    $code = obtainAuthorizationCode($this, $pkce);

    $this->post('/oauth/token', codeRedemption($this, $code, $pkce, ['code_verifier' => null]))
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_request');

    $this->post('/oauth/token', codeRedemption($this, $code, $pkce, ['code_verifier' => 'too-short']))
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_request');

    $this->post('/oauth/token', codeRedemption($this, $code, $pkce, ['code_verifier' => str_repeat('x', 64)]))
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_grant');
});

it('issues no refresh token to a client without the refresh_token grant', function (): void {
    $this->client->forceFill(['grant_types' => ['authorization_code']])->save();

    $this->authorizeAndApprove($this->user, $this->client, scopes: 'openid')
        ->response->assertOk()->assertJsonMissingPath('refresh_token');
});
