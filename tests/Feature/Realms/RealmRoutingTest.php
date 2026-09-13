<?php

declare(strict_types=1);

/**
 * OpenID Connect Discovery 1.0 §3 (one issuer per realm)
 */

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use Lock\Server\Realms\Http\Middleware\ResolveRealm;
use Lock\Server\Shared\Realms\IssuerResolver;
use Lock\Server\Shared\Realms\RealmResolver;
use Lock\Server\Support\Testing\FakesAuthViews;
use Lock\Server\Tests\Support\Realms\RoutesRealmsByPath;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Response;
use Workbench\App\Models\User;

uses(RoutesRealmsByPath::class, FakesAuthViews::class);

beforeEach(function (): void {
    $this->fakeAuthViews();
    config(['oidc.issuer' => 'https://id.example.com']);
});

it('gives each realm its own issuer and realm-scoped endpoints', function (): void {
    $acme = $this->getJson('/realms/acme/.well-known/openid-configuration')->assertOk()->json();
    $globex = $this->getJson('/realms/globex/.well-known/openid-configuration')->assertOk()->json();

    expect($acme['issuer'])->toBe('https://id.example.com/realms/acme')
        ->and($globex['issuer'])->toBe('https://id.example.com/realms/globex')
        ->and($acme['authorization_endpoint'])->toBe('https://id.example.com/realms/acme/oauth/authorize')
        ->and($acme['token_endpoint'])->toBe('https://id.example.com/realms/acme/oauth/token')
        ->and($acme['jwks_uri'])->toBe('https://id.example.com/realms/acme/.well-known/jwks.json');
});

it('falls back to the configured realm outside a matched route', function (): void {
    config(['oidc.realm' => 'fallback']);

    expect(app(RealmResolver::class)->current()->identifier())->toBe('fallback')
        ->and(app(IssuerResolver::class)->url())->toBe('https://id.example.com/realms/fallback');
});

it('scopes the session cookie to the realm path', function (): void {
    config(['session.cookie' => 'app-session']);
    $response = $this->get('/realms/acme/auth/login');

    $cookie = collect($response->headers->getCookies())
        ->first(fn (Cookie $cookie): bool => $cookie->getName() === 'app-session-oidc-acme');

    expect($cookie)->not->toBeNull()
        ->and($cookie->getPath())->toBe('/realms/acme');
});

it('rejects a realm segment that would collide with the well-known paths', function (): void {
    $this->getJson('/realms/a%2Fb/.well-known/openid-configuration')->assertNotFound();
});

it('preserves the application session when the identity login regenerates its session', function (): void {
    config(['session.cookie' => 'app-session']);
    Route::middleware('web')->get('/app-state', function (Request $request): JsonResponse {
        $request->session()->put('oidc-client.state', 'pending-state');

        return response()->json(['state' => $request->session()->get('oidc-client.state')]);
    });
    $user = User::create(['name' => 'Alice', 'email' => 'alice@example.com', 'password' => bcrypt('password')]);
    $application = $this->get('/app-state')->assertOk();
    $applicationSession = $application->getCookie('app-session')?->getValue();
    expect($applicationSession)->toBeString();
    session()->flush();

    $this->withCookie('app-session', $applicationSession);
    $login = $this->get('/realms/acme/auth/login')->assertOk();
    $providerCookie = collect($login->headers->getCookies())->first(
        fn (Cookie $cookie): bool => $cookie->isHttpOnly() && $cookie->getValue() !== null && $cookie->getValue() !== '',
    ) ?? throw new LogicException('The provider did not issue a session cookie.');
    $providerSession = $login->getCookie($providerCookie->getName())?->getValue();
    session()->flush();

    $this->withCookie($providerCookie->getName(), $providerSession)
        ->post('/realms/acme/auth/login', ['email' => 'alice@example.com', 'password' => 'password'])
        ->assertRedirect();

    $this->assertAuthenticatedAs($user, 'identity');

    expect(session()->getHandler()->read($applicationSession))->toContain('pending-state');
    expect(config('session.cookie'))->toBe('app-session')
        ->and(config('session.path'))->toBe('/')
        ->and(session()->getName())->toBe('app-session');

    Auth::forgetGuards();
    session()->flush();
    Route::middleware('web')->get('/callback-state', fn (Request $request): JsonResponse => response()->json(['state' => $request->session()->pull('oidc-client.state')]));
    $this->get('/callback-state')->assertOk()->assertJsonPath('state', 'pending-state');
});

it('expires legacy cookies and clears the provider csrf cookie on external redirects', function (string $location, bool $inertia, bool $leavesRealm): void {
    config(['session.cookie' => 'app-session']);
    Route::middleware([ResolveRealm::class, 'web'])->get('/realms/{realm}/leave', fn (): Response => $inertia
        ? response()->make('', 409, ['X-Inertia-Location' => $location])
        : redirect()->to($location));

    $response = $this->get('/realms/acme/leave');
    $response->assertCookieExpired('app-session');
    expect($response->getCookie('app-session', decrypt: false)?->getPath())->toBe('/realms/acme');

    if ($leavesRealm) {
        $response->assertCookieExpired('XSRF-TOKEN');
    } else {
        $response->assertCookieNotExpired('XSRF-TOKEN');
    }
})->with([
    'callback' => ['/login/callback', false, true],
    'inertia callback' => ['/login/callback', true, true],
    'realm login' => ['/realms/acme/auth/login', false, false],
    'other realm' => ['/realms/partners/auth/login', false, true],
    'other host same path' => ['https://other.test/realms/acme/auth/login', false, true],
]);

it('restores cookie configuration after an exception', function (): void {
    config(['session.cookie' => 'app-session']);
    Route::middleware([ResolveRealm::class, 'web'])->get('/realms/{realm}/broken', fn (): never => abort(503));

    $this->get('/realms/acme/broken')->assertServiceUnavailable();

    expect(config('session.cookie'))->toBe('app-session')
        ->and(config('session.path'))->toBe('/')
        ->and(session()->getName())->toBe('app-session');
});

it('validates logout csrf against the application session after returning from the provider', function (): void {
    config(['session.cookie' => 'app-session']);
    Route::middleware('web')->get('/application', fn (): Response => response()->make('app'));
    Route::middleware('web')->post('/application/logout', fn (): Response => response()->noContent());
    Route::middleware([ResolveRealm::class, 'web'])->get('/realms/{realm}/return', fn (): Response => redirect()->to('/application'));
    app()->instance('env', 'production');

    try {
        $application = $this->get('/application')->assertOk();
        $this->withCookie('app-session', $application->getCookie('app-session')?->getValue());
        $csrf = $application->getCookie('XSRF-TOKEN', decrypt: false)?->getValue();
        session()->flush();
        $this->get('/realms/acme/return')->assertRedirect('/application')->assertCookieExpired('XSRF-TOKEN');

        session()->flush();
        $this->post('/application/logout')->assertStatus(419);
        session()->flush();
        $this->post('/application/logout', [], ['X-XSRF-TOKEN' => $csrf])->assertNoContent();
    } finally {
        app()->instance('env', 'testing');
    }
});

it('rejects a realm cookie name that collides with the application or is invalid', function (string $cookie): void {
    config(['session.cookie' => 'app-session', 'oidc.session.cookie_name' => $cookie]);
    $this->get('/realms/acme/auth/login')->assertServerError();
    expect(config('session.cookie'))->toBe('app-session')->and(config('session.path'))->toBe('/');
})->with(['app-session', 'bad name', 'bad;name']);
