<?php

declare(strict_types=1);

use Illuminate\Http\Response;
use Illuminate\Support\Facades\Route;
use Lock\Server\Authentication\Models\PasswordResetToken;
use Lock\Server\Clients\ClientRepository;
use Lock\Server\Realms\ConfiguredRealm;
use Lock\Server\Realms\Http\Middleware\ResolveRealm;
use Lock\Server\Realms\RealmRepository;
use Lock\Server\Shared\Realms\Realm;
use Lock\Server\Shared\Realms\RealmResolver;
use Lock\Server\Shared\Realms\Settings\AuthenticationSettings;
use Lock\Server\Shared\Realms\Settings\BrokeringSettings;
use Lock\Server\Shared\Realms\Settings\ClientSettings;
use Lock\Server\Shared\Realms\Settings\CredentialSettings;
use Lock\Server\Shared\Realms\Settings\KeySettings;
use Lock\Server\Shared\Realms\Settings\LoginSettings;
use Lock\Server\Shared\Realms\Settings\ResourceSettings;
use Lock\Server\Shared\Realms\Settings\ScopeSettings;
use Lock\Server\Shared\Realms\Settings\SessionSettings;
use Lock\Server\Shared\Realms\Settings\TokenSettings;
use Lock\Server\Tests\Support\Realms\RoutesRealmsByPath;

uses(RoutesRealmsByPath::class);

function realmWithSettings(string $id, ?TokenSettings $tokens = null, ?ClientSettings $clients = null, ?SessionSettings $sessions = null): Realm
{
    return new readonly class($id, $tokens, $clients, $sessions) implements Realm
    {
        private ConfiguredRealm $configured;

        public function __construct(string $id, private ?TokenSettings $tokenSettings, private ?ClientSettings $clientSettings, private ?SessionSettings $sessionSettings)
        {
            $this->configured = new ConfiguredRealm($id);
        }

        public function identifier(): string
        {
            return $this->configured->identifier();
        }

        public function host(): ?string
        {
            return $this->configured->host();
        }

        public function tokens(): TokenSettings
        {
            return $this->tokenSettings ?? $this->configured->tokens();
        }

        public function resources(): ResourceSettings
        {
            return $this->configured->resources();
        }

        public function sessions(): SessionSettings
        {
            return $this->sessionSettings ?? $this->configured->sessions();
        }

        public function login(): LoginSettings
        {
            return $this->configured->login();
        }

        public function authentication(): AuthenticationSettings
        {
            return $this->configured->authentication();
        }

        public function credentials(): CredentialSettings
        {
            return $this->configured->credentials();
        }

        public function brokering(): BrokeringSettings
        {
            return $this->configured->brokering();
        }

        public function scopes(): ScopeSettings
        {
            return $this->configured->scopes();
        }

        public function clients(): ClientSettings
        {
            return $this->clientSettings ?? $this->configured->clients();
        }

        public function keys(): KeySettings
        {
            return $this->configured->keys();
        }
    };
}

function bindRealms(Realm ...$realms): void
{
    app()->instance(RealmRepository::class, new readonly class($realms) implements RealmRepository
    {
        /** @param  list<Realm>  $realms */
        public function __construct(private array $realms) {}

        public function find(string $id): ?Realm
        {
            foreach ($this->realms as $realm) {
                if ($realm->identifier() === $id) {
                    return $realm;
                }
            }

            return null;
        }

        public function findByDomain(string $host): ?Realm
        {
            return $this->find(explode('.', $host)[0]);
        }
    });
    app()->forgetInstance(RealmResolver::class);
}

it('issues tokens with the lifetime of the realm they are issued in', function (): void {
    config(['oidc.tokens.client_credentials' => 3600]);
    bindRealms(realmWithSettings('default'), realmWithSettings('short', new TokenSettings(clientCredentialsLifetime: 60)));

    $clients = [];

    foreach (['default', 'short'] as $realm) {
        config(['oidc.realm' => $realm]);
        if ($realm !== 'default') {
            generateRealmSigningKey();
        }
        $clients[$realm] = app(ClientRepository::class)->createClientCredentialsGrantClient('M2M');
    }

    $expiresIn = (fn (string $realm): int => (int) $this->post("/realms/{$realm}/oauth/token", [
        'grant_type' => 'client_credentials',
        'client_id' => $clients[$realm]->id,
        'client_secret' => $clients[$realm]->secret,
        'scope' => '',
    ])->assertOk()->json('expires_in'));

    expect($expiresIn('default'))->toBeGreaterThan(3300)
        ->and($expiresIn('short'))->toBeLessThanOrEqual(60);
});

it('answers 404 for a realm the repository does not know', function (): void {
    bindRealms(realmWithSettings('default'));

    $this->get('/realms/ghost/.well-known/openid-configuration')->assertNotFound();
    $this->get('/realms/default/.well-known/openid-configuration')->assertOk();
});

it('advertises token exchange and registration per realm', function (): void {
    bindRealms(
        realmWithSettings('default'),
        realmWithSettings('locked', clients: new ClientSettings(dynamicRegistration: false, tokenExchange: false)),
    );
    config(['oidc.clients.registration.enabled' => true]);

    $open = $this->getJson('/realms/default/.well-known/openid-configuration')->json();
    $locked = $this->getJson('/realms/locked/.well-known/openid-configuration')->json();

    expect($open['grant_types_supported'])->toContain('urn:ietf:params:oauth:grant-type:token-exchange')
        ->and($open)->toHaveKey('registration_endpoint')
        ->and($locked['grant_types_supported'])->not->toContain('urn:ietf:params:oauth:grant-type:token-exchange')
        ->and($locked)->not->toHaveKey('registration_endpoint');
});

it('uses each realms configured session cookie while keeping the app cookie unchanged', function (): void {
    config(['session.cookie' => 'app-session', 'oidc.session.cookie_name' => 'configured-provider']);
    bindRealms(
        realmWithSettings('default'),
        realmWithSettings('partners', sessions: new SessionSettings(cookieName: 'partners-identity')),
    );
    Route::middleware([ResolveRealm::class, 'web'])
        ->get('/realms/{realm}/session-cookie', fn (): Response => response()->make('ok'));

    $this->get('/realms/default/session-cookie')->assertOk()->assertCookie('configured-provider');
    $this->get('/realms/partners/session-cookie')->assertOk()->assertCookie('partners-identity');
    expect(config('session.cookie'))->toBe('app-session');
});

it('creates clients with the scope assignment of their realm', function (): void {
    bindRealms(
        realmWithSettings('default'),
        realmWithSettings('strict', clients: new ClientSettings(defaultScopes: ['openid'], optionalScopes: ['email'])),
    );

    config(['oidc.realm' => 'strict']);
    $strict = app(ClientRepository::class)->createClientCredentialsGrantClient('M2M');
    config(['oidc.realm' => 'default']);
    $open = app(ClientRepository::class)->createClientCredentialsGrantClient('M2M');

    expect($strict->default_scopes)->toBe(['openid'])
        ->and($strict->optional_scopes)->toBe(['email'])
        ->and($open->default_scopes)->toBe([])
        ->and($open->optional_scopes)->toBe(['*']);
});

it('prunes reset links using each realms lifetime without removing valid links', function (): void {
    $this->freezeTime();
    config(['oidc.tokens.password_reset' => 3600]);
    bindRealms(
        realmWithSettings('default'),
        realmWithSettings('long', new TokenSettings(passwordResetLifetime: 7200)),
        realmWithSettings('short', new TokenSettings(passwordResetLifetime: 600)),
    );
    $valid = PasswordResetToken::factory()->create(['realm' => 'long', 'created_at' => now()->subMinutes(90)]);
    PasswordResetToken::factory()->create(['realm' => 'long', 'created_at' => now()->subHours(3)]);
    PasswordResetToken::factory()->create(['realm' => 'short', 'created_at' => now()->subMinutes(20)]);
    PasswordResetToken::factory()->create(['realm' => 'default', 'created_at' => now()->subMinutes(90)]);

    $this->artisan('oidc:prune')->assertSuccessful();

    expect(PasswordResetToken::query()->pluck('id')->all())->toBe([$valid->id]);
    expect(app(RealmResolver::class)->current()->identifier())->toBe('default');
});
