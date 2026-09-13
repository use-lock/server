<?php

declare(strict_types=1);

/**
 * RFC 8707 §2 (resource indicators); OpenID Connect Core §3.1.2.4 (consent)
 */

use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Foundation\Http\Middleware\ValidateCsrfToken;
use Illuminate\Testing\TestResponse;
use Lock\Server\Clients\ClientRepository;
use Lock\Server\Consents\Models\Consent;
use Lock\Server\Support\Testing\InteractsWithOidc;
use Lock\Server\Support\Testing\PkcePair;
use Symfony\Component\HttpFoundation\Response;
use Workbench\App\Models\User;

uses(InteractsWithOidc::class);

const ORDERS = 'https://api.internal/orders';

const BILLING = 'https://api.internal/billing';

beforeEach(function (): void {
    $this->withoutMiddleware([ValidateCsrfToken::class, PreventRequestForgery::class]);
    fakeConsentViewUsing(fn (array $parameters) => response()->json(['authToken' => $parameters['authToken']]));

    config(['oidc.resources' => [ORDERS => ['scopes' => ['read']], BILLING => ['scopes' => ['read']]]]);

    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'email_verified_at' => now(), 'password' => 'x']);
    $this->client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/callback']);
    $this->client->forceFill(['allowed_exchange_audiences' => [ORDERS, BILLING]])->save();
});

/**
 * @param  list<string>  $resources
 * @return TestResponse<Response>
 */
function authorizeForResource(mixed $test, array $resources, string $scope = 'openid read'): TestResponse
{
    return $test->actingAsIdentity($test->user, authTime: time() - 60)
        ->get(route('oidc.authorize').'?'.http_build_query([
            'client_id' => $test->client->client_id,
            'redirect_uri' => 'https://rp.test/callback',
            'response_type' => 'code',
            'scope' => $scope,
            'state' => 'st4te',
            'code_challenge' => PkcePair::generate()->challenge,
            'code_challenge_method' => 'S256',
            'resource' => $resources,
        ]));
}

/** @param  list<string>  $resources */
function approveForResource(mixed $test, array $resources, string $scope = 'openid read'): void
{
    $view = authorizeForResource($test, $resources, $scope)->assertOk();

    $test->post(route('oidc.approve'), ['auth_token' => $view->json('authToken')])->assertRedirect();
}

it('stores the resource the scopes were approved for', function (): void {
    approveForResource($this, [ORDERS]);

    $consent = Consent::query()->sole();

    expect($consent->resource)->toBe(ORDERS)
        ->and($consent->scopes)->toBe(['openid', 'read']);
});

it('asks again for the same scope at a resource the user has not approved', function (): void {
    approveForResource($this, [ORDERS]);

    authorizeForResource($this, [BILLING])->assertOk();
});

it('keeps one consent per resource', function (): void {
    approveForResource($this, [ORDERS]);
    approveForResource($this, [BILLING]);

    expect(Consent::query()->count())->toBe(2)
        ->and(Consent::query()->orderBy('resource')->pluck('resource')->all())->toBe([BILLING, ORDERS]);
});

it('records every named resource and covers them together', function (): void {
    approveForResource($this, [ORDERS, BILLING]);

    expect(Consent::query()->count())->toBe(2);

    authorizeForResource($this, [ORDERS])->assertRedirect();
    authorizeForResource($this, [BILLING])->assertRedirect();
    authorizeForResource($this, [ORDERS, BILLING])->assertRedirect();
});

it('asks again when only one of the named resources is covered', function (): void {
    approveForResource($this, [ORDERS]);

    authorizeForResource($this, [ORDERS, BILLING])->assertOk();
});

it('stores the realm issuer as the resource when no resource is named', function (): void {
    approveForResource($this, [], 'openid');

    expect(Consent::query()->sole()->resource)->toBe(config('app.url'));
});

it('does not let a consent for the realm cover a named resource', function (): void {
    approveForResource($this, [], 'openid');

    authorizeForResource($this, [ORDERS], 'openid')->assertOk();
});
