<?php

declare(strict_types=1);

namespace Lock\Server\SigningKeys;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;
use Lock\Server\Shared\Maintenance\RealmDeleting;
use Lock\Server\Shared\SigningKeys\Keyring;
use Lock\Server\SigningKeys\Commands\RotateKeysCommand;
use Lock\Server\SigningKeys\Listeners\DeleteRealmData;

class SigningKeysServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(SigningKeyStore::class, fn (Application $app): SigningKeyStore => $app->make(
            (string) config('oidc.keys.store', DatabaseSigningKeyStore::class),
        ));
        $this->app->singleton(Keyring::class, StoredKeyring::class);
    }

    public function boot(): void
    {
        Event::listen(RealmDeleting::class, DeleteRealmData::class);

        if ($this->app->runningInConsole()) {
            $this->commands([RotateKeysCommand::class]);
        }
    }
}
