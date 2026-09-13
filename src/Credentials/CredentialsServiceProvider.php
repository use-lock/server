<?php

declare(strict_types=1);

namespace Lock\Server\Credentials;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;
use Laravel\Passkeys\Contracts\PasskeyUser;
use Laravel\Passkeys\Passkeys;
use Lock\Server\Credentials\Listeners\DeleteUserData;
use Lock\Server\Shared\Credentials\FactorOperations as FactorOperationsContract;
use Lock\Server\Shared\Credentials\FactorProvider;
use Lock\Server\Shared\Credentials\FactorRegistry as FactorRegistryContract;
use Lock\Server\Shared\Credentials\PasswordCredential;
use Lock\Server\Shared\Maintenance\UserDeleting;
use Lock\Server\Shared\Realms\RealmResolver;
use LogicException;

class CredentialsServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(TotpFactorProvider::class);
        $this->app->singleton(RecoveryCodeProvider::class);
        $this->app->singleton(WebAuthnFactorProvider::class);
        $this->app->singleton(PasswordCredential::class, TrackedPasswordCredential::class);
        $this->app->singleton(FactorRegistry::class, function (Application $app): FactorRegistry {
            $registry = new FactorRegistry($app->make(RealmResolver::class));

            foreach ((array) config('oidc.credentials.factors', []) as $provider) {
                $resolved = $app->make($provider);

                if (! $resolved instanceof FactorProvider) {
                    throw new LogicException("The configured factor provider [{$provider}] must implement FactorProvider.");
                }

                $registry->register($resolved);
            }

            return $registry;
        });

        $this->app->alias(FactorRegistry::class, FactorRegistryContract::class);
        $this->app->bind(FactorOperationsContract::class, FactorOperations::class);

        $this->configurePasskeyUserModel();
    }

    private function configurePasskeyUserModel(): void
    {
        $userModel = config('auth.providers.users.model');

        if (is_string($userModel) && is_subclass_of($userModel, PasskeyUser::class)) {
            Passkeys::useUserModel($userModel);
        }
    }

    public function boot(): void
    {
        Event::listen(UserDeleting::class, DeleteUserData::class);

    }
}
