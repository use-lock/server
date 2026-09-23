<?php
declare(strict_types=1);

namespace Lock\Server\Tests;

use Carbon\CarbonImmutable;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Date;
use Illuminate\Support\Facades\Http;
use Illuminate\Testing\ParallelTestingServiceProvider;
use Laravel\Passkeys\Passkeys;
use Laravel\Passkeys\PasskeysServiceProvider;
use Lattice\LatticeServiceProvider;
use Lattice\Support\Testing\InteractsWithLatticeComponents;
use Lock\Server\OidcServiceProvider;
use Lock\Server\SigningKeys\GeneratedSigningKeys;
use Lock\Server\SigningKeys\Jwk;
use Lock\Server\SigningKeys\SigningKeyStore;
use Lock\Server\Tests\Support\Realms\RoutesRealmsByDomain;
use Lock\Server\Tests\Support\Realms\RoutesRealmsByPath;
use Orchestra\Testbench\Concerns\WithWorkbench;
use Orchestra\Testbench\TestCase as BaseTestCase;
use Workbench\App\Models\User;
use Workbench\App\Providers\WorkbenchServiceProvider;

use function Orchestra\Testbench\default_migration_path;
use function Orchestra\Testbench\load_migration_paths;

abstract class FeatureTestCase extends BaseTestCase
{
    use InteractsWithLatticeComponents;
    use RefreshDatabase;
    use WithWorkbench;

    protected $enablesPackageDiscoveries = false;

    public const string TOKEN_EXCHANGE_GRANT = 'urn:ietf:params:oauth:grant-type:token-exchange';

    protected function getPackageProviders($app): array
    {
        return [
            ParallelTestingServiceProvider::class,
            PasskeysServiceProvider::class,
            LatticeServiceProvider::class,
            OidcServiceProvider::class,
            WorkbenchServiceProvider::class,
        ];
    }

    protected function getEnvironmentSetUp($app): void
    {
        $app['config']->set('app.key', 'base64:'.base64_encode(random_bytes(32)));
        $app['config']->set('auth.providers.users.model', User::class);
        $app['config']->set('auth.guards.api', ['driver' => 'oidc', 'provider' => 'users']);
        $app['config']->set('session.driver', 'array');

        $uses = class_uses_recursive($this);

        if (in_array(RoutesRealmsByPath::class, $uses, true)) {
            $app['config']->set('oidc.routes.realms', 'path');
        }

        if (in_array(RoutesRealmsByDomain::class, $uses, true)) {
            // Every host must name a realm in `domain` routing, the harness's own included.
            $app['config']->set('oidc.routes.realms', 'domain');
            $app['config']->set('oidc.routes.domains', ['localhost' => 'default']);
        }
    }

    protected function setUp(): void
    {
        Date::use(CarbonImmutable::class);

        parent::setUp();

        Http::preventStrayRequests();

        $this->installFixtureSigningKey();
    }

    /**
     * The fixture keypair keeps kids stable across the suite, so tests may
     * compare against the checked-in public key.
     */
    private function installFixtureSigningKey(): void
    {
        $publicKey = (string) file_get_contents(__DIR__.'/fixtures/oauth-public.key');

        app(SigningKeyStore::class)->rotate(new GeneratedSigningKeys(
            privateKeyPem: (string) file_get_contents(__DIR__.'/fixtures/oauth-private.key'),
            publicKeyPem: $publicKey,
            kid: Jwk::fromPem($publicKey)['kid'],
        ));
    }

    protected function defineDatabaseMigrations(): void
    {
        load_migration_paths($this->app, [
            default_migration_path(),
            __DIR__.'/../workbench/database/migrations',
            Passkeys::migrationPath(),
            __DIR__.'/../database/migrations',
        ]);
    }
}
