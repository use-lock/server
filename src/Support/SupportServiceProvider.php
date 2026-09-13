<?php

declare(strict_types=1);

namespace Lock\Server\Support;

use Illuminate\Support\ServiceProvider;
use Lock\Server\Support\Maintenance\Commands\PruneCommand;
use Lock\Server\Support\Setup\Commands\InstallSelfCommand;
use Lock\Server\Support\Setup\Commands\ProvisionClientCommand;
use Lock\Server\Support\Setup\EnvironmentFile;

class SupportServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(EnvironmentFile::class);
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->commands([InstallSelfCommand::class, ProvisionClientCommand::class, PruneCommand::class]);
        }
    }
}
