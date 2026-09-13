<?php
declare(strict_types=1);

namespace Workbench\App\Providers;

use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;
use Laravel\Boost\Install\GuidelineComposer;
use Laravel\Boost\Install\SkillComposer;
use Laravel\Boost\Support\Config;
use Workbench\App\Support\BoostConfig;
use Workbench\App\Support\BoostGuidelineComposer;
use Workbench\App\Support\BoostSkillComposer;

class WorkbenchServiceProvider extends ServiceProvider
{
    #[\Override]
    public function register(): void
    {
        $this->readBoostConfigFromPackageRoot();
    }

    public function boot(): void
    {
        Route::redirect('/logout', '/')->name('logout');
    }

    /**
     * Boost reads boost.json, .ai/guidelines and .ai/skills relative to base_path(), which
     * under Testbench is the vendor skeleton. Point it at the repository root instead.
     */
    private function readBoostConfigFromPackageRoot(): void
    {
        if (! class_exists(Config::class)) {
            return;
        }

        $this->app->singleton(Config::class, fn (): Config => new BoostConfig);
        $this->app->bind(GuidelineComposer::class, BoostGuidelineComposer::class);
        $this->app->bind(SkillComposer::class, BoostSkillComposer::class);
    }
}
