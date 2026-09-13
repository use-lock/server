<?php

declare(strict_types=1);

/**
 * RFC 8707 §2 (resource at the authorization and token endpoints, invalid_target); RFC 9068 §3 (aud from the
 * resource, the issuer as default resource indicator), §4 (resource-server validation); RFC 6750 §3.1
 */

use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Foundation\Http\Middleware\ValidateCsrfToken;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use Lock\Server\Clients\ClientRepository;
use Lock\Server\Support\Testing\InteractsWithOidc;
use Lock\Server\Support\Testing\PkcePair;
use Lock\Server\Tokens\Http\Middleware\CheckAudience;
use Symfony\Component\HttpFoundation\Response;
use Workbench\App\Models\User;

uses(InteractsWithOidc::class);

const ORDERS_API = 'https://api.internal/orders';

const BILLING_API = 'https://api.internal/billing';

beforeEach(function (): void {
    $this->withoutMiddleware([ValidateCsrfToken::class, PreventRequestForgery::class]);
    fakeConsentViewUsing(fn (array $parameters) => response()->json(['authToken' => $parameters['authToken']]));
    config(['oidc.resources' => [ORDERS_API => [], BILLING_API => []]]);

    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'email_verified_at' => now(), 'password' => 'x']);
    $this->client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/callback']);
    $this->client->forceFill(['allowed_exchange_audiences' => [ORDERS_API, BILLING_API]])->save();

    Route::middleware(['auth:oidc', CheckAudience::using(ORDERS_API)])
        ->get('/test/orders', fn (Request $request) => response()->json(['user' => $request->user()?->getAuthIdentifier()]));
});

/**
 * @param  list<string>  $resources
 * @return TestResponse<Response>
 */
function authorizeFor(mixed $test, PkcePair $pkce, array $resources, string $scope = 'openid'): TestResponse
{
    return $test->actingAsIdentity($test->user, authTime: time() - 60)
        ->get('/oauth/authorize?'.http_build_query([
            'client_id' => $test->client->client_id,
            'redirect_uri' => 'https://rp.test/callback',
            'response_type' => 'code',
            'scope' => $scope,
            'state' => 'st4te',
            'code_challenge' => $pkce->challenge,
            'code_challenge_method' => 'S256',
            'resource' => $resources,
        ]));
}

/**
 * @param  TestResponse<Response>  $response
 * @return array<string, string>
 */
function redirectedTo(TestResponse $response): array
{
    parse_str((string) parse_url((string) $response->headers->get('Location'), PHP_URL_QUERY), $params);

    /** @var array<string, string> $params */
    return $params;
}

/**
 * @param  list<string>  $resources
 */
function authorizationCodeFor(mixed $test, PkcePair $pkce, array $resources, string $scope = 'openid'): string
{
    $authorize = authorizeFor($test, $pkce, $resources, $scope);

    // A consent already granted in this test skips the consent view.
    $approve = $authorize->isRedirect()
        ? $authorize
        : $test->post('/oauth/authorize/consent', ['auth_token' => $authorize->assertOk()->json('authToken')])->assertRedirect();

    return redirectedTo($approve)['code'];
}

/**
 * @param  array<string, mixed>  $overrides
 * @return TestResponse<Response>
 */
function redeem(mixed $test, string $code, PkcePair $pkce, array $overrides = []): TestResponse
{
    return $test->post('/oauth/token', array_merge([
        'grant_type' => 'authorization_code',
        'client_id' => $test->client->client_id,
        'client_secret' => $test->client->secret,
        'redirect_uri' => 'https://rp.test/callback',
        'code' => $code,
        'code_verifier' => $pkce->verifier,
    ], $overrides));
}

/**
 * @param  array<string, mixed>  $overrides
 * @return TestResponse<Response>
 */
function refreshWith(mixed $test, string $refreshToken, array $overrides = []): TestResponse
{
    return $test->post('/oauth/token', array_merge([
        'grant_type' => 'refresh_token',
        'client_id' => $test->client->client_id,
        'client_secret' => $test->client->secret,
        'refresh_token' => $refreshToken,
    ], $overrides));
}

it('binds the token to the resources named at the authorization endpoint and keeps them across refresh', function (): void {
    $pkce = $this->pkce();
    $first = redeem($this, authorizationCodeFor($this, $pkce, [ORDERS_API, BILLING_API]), $pkce)->assertOk();

    expect(parseAccessToken((string) $first->json('access_token'))->claims()->get('aud'))->toBe([ORDERS_API, BILLING_API]);

    $this->getJson('/test/orders', ['Authorization' => 'Bearer '.$first->json('access_token')])->assertOk();

    $refreshed = refreshWith($this, (string) $first->json('refresh_token'))->assertOk();

    expect(parseAccessToken((string) $refreshed->json('access_token'))->claims()->get('aud'))->toBe([ORDERS_API, BILLING_API]);
});

it('narrows the token to a subset of the granted resources at the token endpoint and on refresh', function (): void {
    $pkce = $this->pkce();
    $narrowed = redeem($this, authorizationCodeFor($this, $pkce, [ORDERS_API, BILLING_API]), $pkce, ['resource' => ORDERS_API])->assertOk();

    expect(parseAccessToken((string) $narrowed->json('access_token'))->claims()->get('aud'))->toBe([ORDERS_API]);

    refreshWith($this, (string) $narrowed->json('refresh_token'), ['resource' => BILLING_API])
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_target');
});

it('refuses a resource at the token endpoint that the authorization request did not name', function (): void {
    $pkce = $this->pkce();

    redeem($this, authorizationCodeFor($this, $pkce, [ORDERS_API]), $pkce, ['resource' => BILLING_API])
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_target');
});

it('refuses a login token at a resource route and accepts one requested for that resource', function (): void {
    $issuerOnly = $this->authorizeAndApprove($this->user, $this->client);

    $this->getJson('/test/orders', ['Authorization' => "Bearer {$issuerOnly->accessToken}"])
        ->assertUnauthorized()
        ->assertJsonPath('error', 'invalid_token');

    Auth::forgetGuards();

    $pkce = $this->pkce();
    $forOrders = redeem($this, authorizationCodeFor($this, $pkce, [ORDERS_API]), $pkce)->assertOk();

    $this->getJson('/test/orders', ['Authorization' => 'Bearer '.$forOrders->json('access_token')])
        ->assertOk()
        ->assertJson(['user' => $this->user->id]);
});

it('keeps a scope its resource owns out of a request that does not name that resource, wildcard assignment or not', function (): void {
    config([
        'oidc.scopes' => ['orders:read' => 'Read orders'],
        'oidc.resources' => [ORDERS_API => ['scopes' => ['orders:read']], BILLING_API => []],
    ]);
    $pkce = $this->pkce();

    expect($this->client->optional_scopes)->toBe(['*'])
        ->and(redirectedTo(authorizeFor($this, $pkce, [], 'openid orders:read'))['error'])->toBe('invalid_scope')
        ->and(redirectedTo(authorizeFor($this, $pkce, [BILLING_API], 'openid orders:read'))['error'])->toBe('invalid_scope');

    $granted = redeem($this, authorizationCodeFor($this, $pkce, [ORDERS_API], 'openid orders:read'), $pkce)->assertOk();

    expect($granted->json('scope'))->toBe('openid orders:read');
});

it('reads the same scope value under two resources as two different scopes', function (): void {
    config([
        'oidc.scopes' => ['read' => 'Read things'],
        'oidc.resources' => [ORDERS_API => ['scopes' => ['read']], BILLING_API => ['scopes' => ['read']]],
    ]);
    $pkce = $this->pkce();

    foreach ([ORDERS_API, BILLING_API] as $resource) {
        expect(redeem($this, authorizationCodeFor($this, $pkce, [$resource], 'openid read'), $pkce)->assertOk()->json('scope'))
            ->toBe('openid read');
    }

    expect(redirectedTo(authorizeFor($this, $pkce, [], 'openid read'))['error'])->toBe('invalid_scope');
});

it('drops a scope the narrowed resource does not own when the token endpoint narrows the audience', function (): void {
    config([
        'oidc.scopes' => ['orders:read' => 'Read orders', 'billing:pay' => 'Pay bills'],
        'oidc.resources' => [ORDERS_API => ['scopes' => ['orders:read']], BILLING_API => ['scopes' => ['billing:pay']]],
    ]);
    $pkce = $this->pkce();
    $code = authorizationCodeFor($this, $pkce, [ORDERS_API, BILLING_API], 'openid orders:read billing:pay');

    expect(redeem($this, $code, $pkce, ['resource' => ORDERS_API])->assertOk()->json('scope'))
        ->toBe('openid orders:read');
});

it('limits a resource-qualified client assignment to requests for that resource', function (): void {
    config([
        'oidc.scopes' => ['read' => 'Read things'],
        'oidc.resources' => [ORDERS_API => ['scopes' => ['read']], BILLING_API => ['scopes' => ['read']]],
    ]);
    $this->client->forceFill(['optional_scopes' => ['openid', ORDERS_API.' read']])->save();
    $pkce = $this->pkce();

    expect(redirectedTo(authorizeFor($this, $pkce, [BILLING_API], 'openid read'))['error'])->toBe('invalid_scope')
        ->and(redeem($this, authorizationCodeFor($this, $pkce, [ORDERS_API], 'openid read'), $pkce)->assertOk()->json('scope'))
        ->toBe('openid read');
});
