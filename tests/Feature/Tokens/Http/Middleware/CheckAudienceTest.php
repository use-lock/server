<?php

declare(strict_types=1);

/**
 * RFC 9068 §4 (aud narrowed per route); RFC 6750 §3.1 (a token for another resource is invalid_token, not insufficient_scope)
 */

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use Lock\Server\Clients\ClientRepository;
use Lock\Server\Tokens\Http\Middleware\CheckAudience;
use Workbench\App\Models\User;

enum ProbeResource: string
{
    case Orders = 'orders';
    case Reports = 'https://other/api';
}

const CHECK_AUDIENCE_CHALLENGE = 'Bearer realm="default", error="invalid_token", resource_metadata="http://localhost/.well-known/oauth-protected-resource"';

beforeEach(function (): void {
    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    $this->client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/cb']);

    // CheckAudience only narrows what the oidc guard already accepted, so both audiences used
    // below must be resources the guard itself recognizes.
    config()->set('oidc.resources', ['https://api.internal/orders' => [], 'https://other/api' => []]);

    Route::middleware(['auth:oidc', CheckAudience::using('https://api.internal/orders')])
        ->get('/test/orders', fn (Request $request) => response()->json(['user' => $request->user()?->getAuthIdentifier()]));
});

it('passes a token addressed to the route audience and rejects one addressed elsewhere', function (): void {
    $orders = resourceServerBearer($this, ['https://api.internal/orders']);
    $other = resourceServerBearer($this, ['https://other/api']);

    $this->getJson('/test/orders', ['Authorization' => "Bearer $orders"])
        ->assertOk()
        ->assertJson(['user' => $this->user->id]);

    // The guard instance caches the user it resolved; drop it so the second bearer is validated afresh.
    Auth::forgetGuards();

    $this->getJson('/test/orders', ['Authorization' => "Bearer $other"])
        ->assertUnauthorized()
        ->assertJsonPath('error', 'invalid_token')
        ->assertHeader('WWW-Authenticate', CHECK_AUDIENCE_CHALLENGE);
});

it('resolves a path-relative resource, given as a string or a backed enum, under the realm issuer', function (): void {
    config()->set('oidc.resources', ['orders' => [], 'https://other/api' => []]);

    Route::middleware(['auth:oidc', CheckAudience::using('orders')])
        ->get('/test/relative', fn (Request $request) => response()->json(['user' => $request->user()?->getAuthIdentifier()]));
    Route::middleware(['auth:oidc', CheckAudience::using(ProbeResource::Orders)])
        ->get('/test/enum', fn (Request $request) => response()->json(['user' => $request->user()?->getAuthIdentifier()]));
    Route::middleware(['auth:oidc', CheckAudience::using(ProbeResource::Reports)])
        ->get('/test/enum-absolute', fn (Request $request) => response()->json(['user' => $request->user()?->getAuthIdentifier()]));

    expect(CheckAudience::using(ProbeResource::Orders, 'https://other/api'))->toBe(CheckAudience::class.':orders,https://other/api');

    $orders = resourceServerBearer($this, ['http://localhost/orders']);
    $other = resourceServerBearer($this, ['https://other/api']);

    $this->getJson('/test/relative', ['Authorization' => "Bearer $orders"])->assertOk()->assertJson(['user' => $this->user->id]);

    Auth::forgetGuards();

    $this->getJson('/test/enum', ['Authorization' => "Bearer $orders"])->assertOk()->assertJson(['user' => $this->user->id]);

    Auth::forgetGuards();

    $this->getJson('/test/enum', ['Authorization' => "Bearer $other"])
        ->assertUnauthorized()
        ->assertJsonPath('error', 'invalid_token');

    Auth::forgetGuards();

    $this->getJson('/test/enum-absolute', ['Authorization' => "Bearer $other"])->assertOk()->assertJson(['user' => $this->user->id]);
});

it('rejects with invalid_token when no preceding guard populated the user', function (): void {
    Route::middleware(CheckAudience::using('https://api.internal/orders'))
        ->get('/test/orders-unguarded', fn (Request $request) => response()->json(['user' => $request->user()?->getAuthIdentifier()]));

    $jwt = resourceServerBearer($this, ['https://api.internal/orders']);

    $this->getJson('/test/orders-unguarded', ['Authorization' => "Bearer $jwt"])
        ->assertUnauthorized()
        ->assertJsonPath('error', 'invalid_token')
        ->assertHeader('WWW-Authenticate', CHECK_AUDIENCE_CHALLENGE);
});

it('narrows a machine token to the route audience the same way', function (): void {
    $machine = app(ClientRepository::class)->createClientCredentialsGrantClient('M2M');
    $orders = clientCredentialsBearer($machine, audience: ['https://api.internal/orders']);
    $other = clientCredentialsBearer($machine, audience: ['https://other/api']);

    $this->getJson('/test/orders', ['Authorization' => "Bearer $orders"])
        ->assertOk()
        ->assertJson(['user' => $machine->client_id]);

    Auth::forgetGuards();

    $this->getJson('/test/orders', ['Authorization' => "Bearer $other"])
        ->assertUnauthorized()
        ->assertJsonPath('error', 'invalid_token')
        ->assertHeader('WWW-Authenticate', CHECK_AUDIENCE_CHALLENGE);
});
