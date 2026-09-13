<?php

declare(strict_types=1);

namespace Lock\Server\Brokering;

use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;
use Lock\Server\Brokering\Listeners\DeleteRealmData;
use Lock\Server\Brokering\Listeners\DeleteUserData;
use Lock\Server\Shared\Brokering\SocialAccounts;
use Lock\Server\Shared\Brokering\SocialProviderRegistry as SocialProviderRegistryContract;
use Lock\Server\Shared\Maintenance\RealmDeleting;
use Lock\Server\Shared\Maintenance\UserDeleting;

class BrokeringServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(SocialProviderRegistry::class);
        $this->app->alias(SocialProviderRegistry::class, SocialProviderRegistryContract::class);
        $this->app->bind(SocialAccounts::class, SocialAccountManager::class);
    }

    public function boot(): void
    {
        Event::listen(UserDeleting::class, DeleteUserData::class);
        Event::listen(RealmDeleting::class, DeleteRealmData::class);

    }
}
