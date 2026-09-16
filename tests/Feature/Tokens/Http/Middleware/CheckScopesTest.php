<?php

declare(strict_types=1);

/**
 * RFC 6750 §3.1 (insufficient_scope) — scope middleware behind the auth:oidc guard
 */

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use Lock\Server\Clients\ClientRepository;
use Lock\Server\Tokens\Http\Middleware\CheckScopes;
use Workbench\App\Models\User;

enum ProbeScope: string
{
    case OpenId = 'openid';
    case Admin = 'admin';
}

beforeEach(function (): void {
    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    $this->client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/cb']);

    Route::middleware(['auth:oidc', CheckScopes::using('openid')])->get('/probe/openid', fn (): array => ['id' => auth()->id()]);
    Route::middleware(['auth:oidc', CheckScopes::using('admin')])->get('/probe/admin', fn (): array => ['id' => auth()->id()]);
});

it('passes a token that carries the required scope and forbids one that lacks it', function (): void {
    $jwt = resourceServerBearer($this);

    $this->getJson('/probe/openid', ['Authorization' => "Bearer $jwt"])
        ->assertOk()
        ->assertJson(['id' => $this->user->getKey()]);

    // The guard instance caches the user it resolved; drop it so the second request is validated afresh.
    Auth::forgetGuards();

    $this->getJson('/probe/admin', ['Authorization' => "Bearer $jwt"])->assertForbidden();
});

it('accepts backed enums as scopes', function (): void {
    Route::middleware(['auth:oidc', CheckScopes::using(ProbeScope::OpenId)])->get('/probe/enum-openid', fn (): array => ['id' => auth()->id()]);
    Route::middleware(['auth:oidc', CheckScopes::using(ProbeScope::OpenId, ProbeScope::Admin)])->get('/probe/enum-admin', fn (): array => ['id' => auth()->id()]);

    expect(CheckScopes::using(ProbeScope::OpenId, 'profile'))->toBe(CheckScopes::class.':openid,profile');

    $jwt = resourceServerBearer($this);

    $this->getJson('/probe/enum-openid', ['Authorization' => "Bearer $jwt"])->assertOk();

    Auth::forgetGuards();

    $this->getJson('/probe/enum-admin', ['Authorization' => "Bearer $jwt"])
        ->assertForbidden()
        ->assertJsonPath('error', 'insufficient_scope');
});

it('checks the scopes of a machine token the same way', function (): void {
    $machine = app(ClientRepository::class)->createClientCredentialsGrantClient('M2M');
    $jwt = clientCredentialsBearer($machine, ['openid']);

    $this->getJson('/probe/openid', ['Authorization' => "Bearer $jwt"])
        ->assertOk()
        ->assertJson(['id' => $machine->client_id]);

    Auth::forgetGuards();

    $this->getJson('/probe/admin', ['Authorization' => "Bearer $jwt"])
        ->assertForbidden()
        ->assertJsonPath('error', 'insufficient_scope');
});
