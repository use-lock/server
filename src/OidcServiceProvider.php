<?php

declare(strict_types=1);

namespace Lock\Server;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Foundation\CachesConfiguration;
use Illuminate\Foundation\Console\AboutCommand;
use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Support\Arr;
use Illuminate\Support\ServiceProvider;
use Lattice\Core\Facades\Lattice;
use Lattice\Http\Middleware\UseEndpointArea;
use Lock\Server\Audit\AuditServiceProvider;
use Lock\Server\Authentication\AuthenticationServiceProvider;
use Lock\Server\Brokering\BrokeringServiceProvider;
use Lock\Server\Clients\ClientsServiceProvider;
use Lock\Server\Consents\ConsentsServiceProvider;
use Lock\Server\Credentials\CredentialsServiceProvider;
use Lock\Server\Protocol\ProtocolServiceProvider;
use Lock\Server\Realms\Enums\RealmRouting;
use Lock\Server\Realms\Http\Middleware\ResolveRealm;
use Lock\Server\Realms\RealmsServiceProvider;
use Lock\Server\Scopes\ScopesServiceProvider;
use Lock\Server\Sessions\SessionsServiceProvider;
use Lock\Server\Sessions\SessionTokenGuard;
use Lock\Server\Shared\Authentication\IdentityGuard;
use Lock\Server\Shared\Clients\FirstPartyClientConfig;
use Lock\Server\SigningKeys\DatabaseSigningKeyStore;
use Lock\Server\SigningKeys\SigningKeysServiceProvider;
use Lock\Server\SigningKeys\SigningKeyStore;
use Lock\Server\Support\SupportServiceProvider;
use Lock\Server\Tokens\TokensServiceProvider;
use Throwable;

class OidcServiceProvider extends ServiceProvider
{
    /**
     * Each domain wires its own bindings, listeners and commands; this
     * provider owns what spans them: config, routes and publishing.
     *
     * @var list<class-string<ServiceProvider>>
     */
    private const array DOMAIN_PROVIDERS = [
        RealmsServiceProvider::class,
        SigningKeysServiceProvider::class,
        ScopesServiceProvider::class,
        CredentialsServiceProvider::class,
        BrokeringServiceProvider::class,
        ClientsServiceProvider::class,
        TokensServiceProvider::class,
        AuthenticationServiceProvider::class,
        SessionsServiceProvider::class,
        ConsentsServiceProvider::class,
        AuditServiceProvider::class,
        ProtocolServiceProvider::class,
        SupportServiceProvider::class,
    ];

    /**
     * Config keys holding a registry: a map of named entries the package ships
     * defaults for. `mergeConfigFrom` merges only the first level, so a
     * published `config/oidc.php` would freeze these maps at the shape they had
     * when it was published and never see an entry a later release adds. This
     * is what Laravel's own loader does for `database.connections` and its
     * siblings (`LoadConfiguration::mergeableOptions`): merge the map by name,
     * so the application's entry always wins whole and is never patched into.
     *
     * Merging runs at every segment of the path, so a registry nested under a
     * group keeps that group's other keys too — without it, an application that
     * defines `social.providers` would lose `social.link_by_verified_email`.
     * Only the declared paths are descended into; nothing else is.
     *
     * `resources` and `routes.domains` ship empty today; they are listed
     * because they are registries, not because they currently merge anything.
     *
     * @var list<string>
     */
    private const array MERGEABLE_REGISTRIES = [
        'resources',
        'social.providers',
        'routes.domains',
    ];

    public function register(): void
    {
        $this->mergeConfig();
        $this->mergeConfigFrom(__DIR__.'/../config/oidc-ui.php', 'oidc-ui');
        config(['oidc.routes.screen_middleware' => [UseEndpointArea::class.':oidc-ui']]);

        foreach (self::DOMAIN_PROVIDERS as $provider) {
            $this->app->register($provider);
        }
    }

    public function boot(): void
    {
        Lattice::endpoints(
            'oidc-ui',
            prefix: trim(RealmRouting::configured()->prefix().'/oidc-ui', '/'),
            middleware: [ResolveRealm::class, 'web'],
        );

        Lattice::translations('oidc-ui', __DIR__.'/../resources/lang');

        $this->publishes([
            __DIR__.'/../config/oidc-ui.php' => config_path('oidc-ui.php'),
        ], 'oidc-ui-config');

        $this->publishes([
            __DIR__.'/../resources/lang' => lang_path('vendor/oidc-ui'),
        ], 'oidc-ui-lang');

        // OIDC Core §3.1.2.1: clients POST authorization requests cross-site,
        // so the web group's forgery check must not apply to that route.
        PreventRequestForgery::except(RealmRouting::configured()->pattern('oauth/authorize'));

        $this->loadRoutesFrom(__DIR__.'/../routes/oidc.php');

        $this->publishes([
            __DIR__.'/../config/oidc.php' => config_path('oidc.php'),
        ], 'oidc-config');

        $this->publishesMigrations([
            __DIR__.'/../database/migrations' => database_path('migrations'),
        ], 'oidc-migrations');

        AboutCommand::add('OIDC', fn (): array => [
            'Issuer' => config('oidc.issuer') ?? 'not set',
            'Auth Guard' => IdentityGuard::name(),
            'Session Token Guard' => SessionTokenGuard::name() ?? 'not set',
            'Self-SSO Client' => FirstPartyClientConfig::fromConfig()->isConfigured() ? 'configured' : 'not configured',
            'Signing Key Store' => class_basename((string) config('oidc.keys.store', DatabaseSigningKeyStore::class)),
            'Signing Key' => $this->activeSigningKid(),
        ]);
    }

    private function mergeConfig(): void
    {
        $path = __DIR__.'/../config/oidc.php';

        $this->mergeConfigFrom($path, 'oidc');

        if ($this->app instanceof CachesConfiguration && $this->app->configurationIsCached()) {
            return;
        }

        $shipped = require $path;
        $config = $this->app->make(ConfigRepository::class);

        foreach (self::MERGEABLE_REGISTRIES as $registry) {
            $walked = [];

            foreach (explode('.', $registry) as $segment) {
                $walked[] = $segment;
                $key = implode('.', $walked);

                $defaults = Arr::get($shipped, $key);
                $configured = $config->get("oidc.{$key}");

                if (is_array($defaults) && is_array($configured)) {
                    $config->set("oidc.{$key}", array_merge($defaults, $configured));
                }
            }
        }
    }

    private function activeSigningKid(): string
    {
        try {
            return $this->app->make(SigningKeyStore::class)->signingKey()->kid();
        } catch (Throwable) {
            return 'missing';
        }
    }
}
