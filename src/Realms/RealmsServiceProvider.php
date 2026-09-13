<?php

declare(strict_types=1);

namespace Lock\Server\Realms;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Routing\Route;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\URL;
use Illuminate\Support\ServiceProvider;
use Lock\Server\Realms\Enums\RealmRouting;
use Lock\Server\Realms\Http\Middleware\ResolveRealm;
use Lock\Server\Shared\Realms\IssuerResolver;
use Lock\Server\Shared\Realms\RealmResolver;

class RealmsServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(RealmRepository::class, ConfiguredRealmRepository::class);
        $this->app->singleton(RealmResolver::class, function (Application $app): RealmResolver {
            $repository = $app->make(RealmRepository::class);
            $configured = new ConfiguredRealmResolver($repository);

            return RealmRouting::configured() === RealmRouting::Domain
                ? new DomainRealmResolver($repository, $configured)
                : new RouteRealmResolver($repository, $configured);
        });
        $this->app->singleton(IssuerResolver::class, RealmIssuerResolver::class);
    }

    public function boot(): void
    {
        // Route generation outside a matched route — console commands, queued
        // notifications — has no realm to fall back on; ResolveRealm overrides
        // this per request.
        URL::defaults(['realm' => (string) config('oidc.realm', 'default')]);

        // A link to a realm's pages belongs on that realm's host whichever host
        // mints it: a password reset sent from an admin console, a verification
        // mail rendered by a queue worker.
        if (RealmRouting::configured() === RealmRouting::Domain) {
            URL::formatHostUsing(fn (string $root, mixed $route): string => $route instanceof Route && ResolveRealm::appliesTo($route)
                ? app(IssuerResolver::class)->url()
                : $root);
        }

        Queue::before(fn () => $this->app->make(ResolveRealmForJob::class)());
    }
}
