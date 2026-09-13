<?php

declare(strict_types=1);

namespace Lock\Server\Clients;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;
use Lock\Server\Clients\Listeners\DeleteRealmData;
use Lock\Server\Clients\Listeners\DeleteUserData;
use Lock\Server\Shared\Clients\ClientProvisioner;
use Lock\Server\Shared\Clients\Clients;
use Lock\Server\Shared\Clients\FirstPartyClientConfig;
use Lock\Server\Shared\Clients\RegisterClient;
use Lock\Server\Shared\Maintenance\RealmDeleting;
use Lock\Server\Shared\Maintenance\UserDeleting;
use Lock\Server\Shared\Realms\RealmResolver;

class ClientsServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->bind(
            FirstPartyClientConfig::class,
            fn (Application $app): FirstPartyClientConfig => FirstPartyClientConfig::fromSettings($app->make(RealmResolver::class)->current()->clients()),
        );
        $this->app->singleton(ClientProvisioner::class, FirstPartyClientProvisioner::class);
        $this->app->bind(Clients::class, ClientRepository::class);
        $this->app->bind(RegisterClient::class, Actions\RegisterClient::class);
    }

    public function boot(): void
    {
        Event::listen(UserDeleting::class, DeleteUserData::class);
        Event::listen(RealmDeleting::class, DeleteRealmData::class);

    }
}
