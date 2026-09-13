<?php

declare(strict_types=1);

/**
 * OpenID Connect Discovery 1.0 §3, RFC 8414 §3.1 (issuer without a path component)
 */

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Lock\Server\Shared\Realms\RealmResolver;
use Lock\Server\Support\Testing\FakesAuthViews;
use Symfony\Component\HttpFoundation\Cookie;
use Workbench\App\Models\User;

uses(FakesAuthViews::class);

beforeEach(function (): void {
    $this->fakeAuthViews();
    config(['oidc.issuer' => 'https://id.example.com']);
});

it('serves the configured realm from the application root with the origin as issuer', function (): void {
    config(['oidc.realm' => 'acme']);

    $this->getJson('/.well-known/openid-configuration')
        ->assertOk()
        ->assertJsonPath('issuer', 'https://id.example.com')
        ->assertJsonPath('authorization_endpoint', 'https://id.example.com/oauth/authorize')
        ->assertJsonPath('token_endpoint', 'https://id.example.com/oauth/token')
        ->assertJsonPath('jwks_uri', 'https://id.example.com/.well-known/jwks.json');

    $this->getJson('/.well-known/oauth-authorization-server')
        ->assertOk()
        ->assertJsonPath('issuer', 'https://id.example.com');

    expect(app(RealmResolver::class)->current()->identifier())->toBe('acme');
});

it('does not route the realm path form', function (): void {
    $this->getJson('/realms/default/.well-known/openid-configuration')->assertNotFound();
    $this->get('/realms/default/auth/login')->assertNotFound();
});

it('leaves the application session cookie untouched', function (): void {
    config(['session.cookie' => 'app-session']);

    $response = $this->get('/auth/login')->assertOk();

    $cookie = collect($response->headers->getCookies())
        ->first(fn (Cookie $cookie): bool => $cookie->getName() === 'app-session');

    expect($cookie)->not->toBeNull()
        ->and($cookie->getPath())->toBe('/')
        ->and(collect($response->headers->getCookies())->pluck('name')->all())->not->toContain('app-session-oidc-default');
});

it('keeps the relying party state in the shared session across an identity login', function (): void {
    Route::middleware('web')->get('/app-state', function (Request $request): JsonResponse {
        $request->session()->put('oidc-client.state', 'pending-state');

        return response()->json();
    });
    $user = User::create(['name' => 'Alice', 'email' => 'alice@example.com', 'password' => bcrypt('password')]);

    $this->get('/app-state')->assertOk();
    $this->post('/auth/login', ['email' => 'alice@example.com', 'password' => 'password'])->assertRedirect();

    $this->assertAuthenticatedAs($user, 'identity');
    expect(session()->get('oidc-client.state'))->toBe('pending-state');
});
