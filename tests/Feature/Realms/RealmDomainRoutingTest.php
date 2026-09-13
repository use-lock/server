<?php

declare(strict_types=1);

/**
 * OpenID Connect Discovery 1.0 §4 (issuer + /.well-known/openid-configuration);
 * RFC 8414 §3.1 (well-known segment ahead of the issuer path)
 */

use Illuminate\Contracts\Auth\CanResetPassword;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Lock\Server\Clients\ClientRepository;
use Lock\Server\Shared\Context\OidcContext;
use Lock\Server\Shared\Realms\CurrentRealm;
use Lock\Server\Shared\Realms\IssuerResolver;
use Lock\Server\Shared\Realms\RealmResolver;
use Lock\Server\Tests\Support\Realms\RecordResolvedRealm;
use Lock\Server\Tests\Support\Realms\RoutesRealmsByDomain;
use Workbench\App\Models\User;

uses(RoutesRealmsByDomain::class);

beforeEach(function (): void {
    config([
        'oidc.issuer' => 'https://localhost',
        'oidc.routes.domains' => [
            'localhost' => 'default',
            'acme.id.test' => 'acme',
            'globex.id.test' => 'globex',
        ],
    ]);
});

it('serves every endpoint at its canonical path, with the well-known segment in front', function (): void {
    $this->getJson('https://acme.id.test/.well-known/openid-configuration')
        ->assertOk()
        ->assertJsonPath('issuer', 'https://acme.id.test')
        ->assertJsonPath('jwks_uri', 'https://acme.id.test/.well-known/jwks.json')
        ->assertJsonPath('token_endpoint', 'https://acme.id.test/oauth/token')
        ->assertJsonPath('authorization_endpoint', 'https://acme.id.test/oauth/authorize');
});

it('gives each host its own issuer', function (): void {
    $this->getJson('https://acme.id.test/.well-known/openid-configuration')
        ->assertOk()
        ->assertJsonPath('issuer', 'https://acme.id.test');

    $this->getJson('https://globex.id.test/.well-known/openid-configuration')
        ->assertOk()
        ->assertJsonPath('issuer', 'https://globex.id.test');
});

// RFC 8414 §3.1 — with no path in the issuer, the well-known segment is all there is
it('serves the authorization server metadata at the bare well-known path', function (): void {
    $this->getJson('https://acme.id.test/.well-known/oauth-authorization-server')
        ->assertOk()
        ->assertJsonPath('issuer', 'https://acme.id.test');
});

it('serves the realm key set from the realm host', function (): void {
    $this->get('https://acme.id.test/.well-known/openid-configuration');
    generateRealmSigningKey();

    $this->getJson('https://acme.id.test/.well-known/jwks.json')
        ->assertOk()
        ->assertJsonCount(1, 'keys');
});

it('answers 404 for a host no realm is served from', function (): void {
    $this->getJson('https://unknown.id.test/.well-known/openid-configuration')->assertNotFound();
});

it('scopes rows to the realm the host names', function (): void {
    $this->get('https://acme.id.test/.well-known/openid-configuration');
    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/cb']);

    expect($client->realm)->toBe('acme');

    $this->get('https://globex.id.test/.well-known/openid-configuration');

    expect(app(ClientRepository::class)->find($client->client_id))->toBeNull();
});

it('resolves the realm a job was dispatched from when there is no host', function (): void {
    config(['queue.default' => 'database', 'oidc.issuer' => 'https://id.example.com']);
    RecordResolvedRealm::forget();

    $this->get('https://acme.id.test/.well-known/openid-configuration')->assertOk();
    RecordResolvedRealm::dispatch();

    forgetRequest();
    workQueue();

    expect(RecordResolvedRealm::$seen['realm'])->toBe('acme')
        ->and(RecordResolvedRealm::$seen['issuer'])->toBe('https://acme.id.test');
});

it('takes the scheme and port of the configured issuer, not of the request', function (): void {
    config(['oidc.issuer' => 'https://id.example.com:8443']);

    $this->getJson('http://acme.id.test/.well-known/openid-configuration')
        ->assertOk()
        ->assertJsonPath('issuer', 'https://acme.id.test:8443')
        ->assertJsonPath('token_endpoint', 'https://acme.id.test:8443/oauth/token');
});

it('links to the realm host from a host that serves another realm', function (): void {
    config(['queue.default' => 'database']);
    RecordResolvedRealm::forget();

    $this->get('https://acme.id.test/.well-known/openid-configuration')->assertOk();
    RecordResolvedRealm::dispatch();

    app()->instance('request', Request::create('https://globex.id.test/'));
    workQueue();

    expect(RecordResolvedRealm::$seen['login_url'])->toBe('https://acme.id.test/auth/login')
        ->and(RecordResolvedRealm::$seen['reset_url'])->toStartWith('https://acme.id.test/auth/reset-password/reset-token');
});

it('serves code run in another realm from that realm, whatever host the request came in on', function (): void {
    $this->get('https://acme.id.test/.well-known/openid-configuration')->assertOk();

    $inGlobex = CurrentRealm::runAs('globex', fn (): array => [
        'realm' => app(RealmResolver::class)->current()->identifier(),
        'issuer' => app(IssuerResolver::class)->url(),
        'login_url' => route('identity.login'),
        'client_realm' => app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/cb'])->realm,
    ]);

    expect($inGlobex)->toBe([
        'realm' => 'globex',
        'issuer' => 'https://globex.id.test',
        'login_url' => 'https://globex.id.test/auth/login',
        'client_realm' => 'globex',
    ])->and(app(RealmResolver::class)->current()->identifier())->toBe('acme');
});

it('restores the realm it interrupted, so runs nest', function (): void {
    app()->instance('request', Request::create('https://localhost/'));

    $seen = CurrentRealm::runAs('acme', fn (): array => [
        CurrentRealm::runAs('globex', fn (): string => app(RealmResolver::class)->current()->identifier()),
        app(RealmResolver::class)->current()->identifier(),
    ]);

    expect($seen)->toBe(['globex', 'acme'])
        ->and(app(RealmResolver::class)->current()->identifier())->toBe('default')
        ->and(OidcContext::realm())->toBeNull();
});

it('hands the realm it runs in to the jobs dispatched inside', function (): void {
    config(['queue.default' => 'database', 'oidc.issuer' => 'https://id.example.com']);
    RecordResolvedRealm::forget();
    app()->instance('request', Request::create('https://localhost/'));

    CurrentRealm::runAs('acme', function (): void {
        RecordResolvedRealm::dispatch();
    });

    forgetRequest();
    workQueue();

    expect(RecordResolvedRealm::$seen['realm'])->toBe('acme')
        ->and(RecordResolvedRealm::$seen['issuer'])->toBe('https://acme.id.test');
});

it('honours a reset link only in the realm that sent it', function (): void {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('old-password')]);
    $token = CurrentRealm::runAs('acme', fn (): string => passwordResetToken($user));
    resetUserPasswordsUsing(function (CanResetPassword $user, array $input): void {
        $user->forceFill(['password' => Hash::make($input['password'])])->save();
    });
    $reset = [
        'token' => $token,
        'email' => 'm@example.com',
        'password' => 'new-password',
        'password_confirmation' => 'new-password',
    ];

    $this->postJson('https://globex.id.test/auth/reset-password', $reset)->assertJsonValidationErrors('email');
    $this->postJson('https://acme.id.test/auth/reset-password', $reset)->assertOk();
});
