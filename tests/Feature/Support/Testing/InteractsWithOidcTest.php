<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Lock\Server\Authentication\Context\LoginState;
use Lock\Server\Support\Testing\InteractsWithOidc;
use Lock\Server\Tokens\TokenInspector;
use Workbench\App\Models\User;

uses(InteractsWithOidc::class);

beforeEach(function (): void {
    fakeConsentViewUsing(fn (array $parameters) => response()->json(['authToken' => $parameters['authToken']]));

    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'email_verified_at' => now(), 'password' => 'x']);
});

it('authenticates on the identity guard and seeds the auth context session keys', function (): void {
    $result = $this->actingAsIdentity(
        $this->user,
        idTokenClaims: ['locale' => 'de'],
        accessTokenClaims: ['tenant' => 't1'],
        amr: ['pwd', 'otp'],
        authTime: 1234567890,
    );

    expect($result)->toBe($this)
        ->and(auth('identity')->id())->toBe($this->user->id)
        ->and(session('oidc.auth_time'))->toBe(1234567890)
        ->and(session(LoginState::AMR_KEY))->toBe(['pwd', 'otp'])
        ->and(session('oidc.id_token_claims'))->toBe(['locale' => 'de'])
        ->and(session('oidc.access_token_claims'))->toBe(['tenant' => 't1']);
});

it('defaults auth_time to now and leaves optional context keys unset', function (): void {
    $this->actingAsIdentity($this->user);

    expect(session('oidc.auth_time'))->toBeGreaterThanOrEqual(time() - 5)
        ->and(session()->has(LoginState::AMR_KEY))->toBeFalse()
        ->and(session()->has('oidc.id_token_claims'))->toBeFalse()
        ->and(session()->has('oidc.access_token_claims'))->toBeFalse();
});

it('configures a trusted first-party client', function (): void {
    $client = $this->withFirstPartyClient();

    expect(config('oidc.clients.first_party.client_id'))->toBe((string) $client->getKey())
        ->and(config('oidc.clients.first_party.trusted'))->toBeTrue();
});

it('mints a real signed access token with a persisted row', function (): void {
    $jwt = $this->issueTokenFor($this->user, scopes: ['openid', 'email'], audience: ['https://api.orders.test']);

    $token = app(TokenInspector::class)->accessToken($jwt);

    expect($token)->not->toBeNull()
        ->and((string) $token?->getAttribute('user_id'))->toBe((string) $this->user->id)
        ->and($token?->getAttribute('scopes'))->toBe(['openid', 'email'])
        ->and($token?->isRevoked())->toBeFalse();

    $bearerJwt = $this->issueTokenFor($this->user, scopes: ['openid', 'email']);

    $this->withHeader('Authorization', 'Bearer '.$bearerJwt)
        ->get('/oauth/userinfo')
        ->assertOk()
        ->assertJsonPath('sub', (string) $this->user->id);
});

it('authenticates a client principal on the token guard and mints a userless token', function (): void {
    $client = $this->createOidcMachineClient();

    $principal = $this->actingAsOidcClient($client, ['orders.read']);

    expect(auth('oidc')->user())->toBe($principal)
        ->and($principal->clientId())->toBe($client->client_id)
        ->and($principal->tokenCan('orders.read'))->toBeTrue()
        ->and($principal->tokenCan('orders.write'))->toBeFalse();

    $token = app(TokenInspector::class)->accessToken($this->issueClientToken($client, ['orders.read']));

    expect($token?->getAttribute('user_id'))->toBeNull()
        ->and($token?->getAttribute('scopes'))->toBe(['orders.read']);
});

it('drives the full authorize-approve-token dance, honoring parameter overrides and prior consent', function (): void {
    $client = $this->createOidcClient();

    $result = $this->authorizeAndApprove($this->user, $client, scopes: 'openid email', params: ['nonce' => 'fixed-nonce']);

    $result->response->assertOk();
    expect($result->accessToken)->toBeString()
        ->and($result->refreshToken)->toBeString()
        ->and(parseIdToken((string) $result->idToken)->claims()->get('nonce'))->toBe('fixed-nonce');

    expect($this->authorizeAndApprove($this->user, $client)->accessToken)->toBeString();
});

it('scopes the CSRF exemption to the authorizeAndApprove flow', function (): void {
    Route::post('/csrf-probe', fn () => response()->noContent())->middleware('web');

    // Both CSRF middlewares short-circuit under the `testing` env, so the probe only enforces
    // once the app stops reporting unit tests. Restored before teardown: confirmable commands
    // would prompt under `production`.
    $this->app->instance('env', 'production');

    try {
        $this->authorizeAndApprove($this->user)->response->assertOk();

        $this->post('/csrf-probe')->assertStatus(419);
    } finally {
        $this->app->instance('env', 'testing');
    }
});

it('returns the raw token error response for a broken token leg', function (): void {
    $confidential = $this->createOidcClient();
    $confidential->secret = 'wrong-secret';

    $result = $this->authorizeAndApprove($this->user, $confidential);

    $result->response->assertStatus(401);
    expect($result->accessToken)->toBeNull()
        ->and($result->response->json('error'))->toBe('invalid_client');
});
