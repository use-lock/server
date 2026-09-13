<?php

declare(strict_types=1);

namespace Lock\Server\Consents;

use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;
use Lock\Server\Consents\Listeners\DeleteUserData;
use Lock\Server\Consents\Ui\Pages\OAuthConsentPage;
use Lock\Server\Shared\Consents\ConsentStore;
use Lock\Server\Shared\Consents\ConsentView;
use Lock\Server\Shared\Maintenance\UserDeleting;

class ConsentsServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(ConsentStore::class, ConsentRepository::class);
        $this->app->bind(ConsentView::class, OAuthConsentPage::class);
    }

    public function boot(): void
    {
        Event::listen(UserDeleting::class, DeleteUserData::class);

    }
}
