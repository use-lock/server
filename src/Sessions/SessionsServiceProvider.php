<?php

declare(strict_types=1);

namespace Lock\Server\Sessions;

use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;
use Lock\Server\Sessions\BackChannel\BackChannelLogoutNotifier;
use Lock\Server\Sessions\Commands\DispatchExpiredSessionLogoutsCommand;
use Lock\Server\Sessions\Contracts\SessionTokenProvider;
use Lock\Server\Sessions\Listeners\DeleteRealmData;
use Lock\Server\Sessions\Listeners\DeleteUserData;
use Lock\Server\Sessions\Listeners\EndOidcSession;
use Lock\Server\Sessions\Listeners\EstablishSessionToken;
use Lock\Server\Sessions\Listeners\ForgetSessionToken;
use Lock\Server\Sessions\Listeners\StartOidcSession;
use Lock\Server\Sessions\Models\OidcSession;
use Lock\Server\Shared\Audit\SessionContext;
use Lock\Server\Shared\Maintenance\RealmDeleting;
use Lock\Server\Shared\Maintenance\UserDeleting;
use Lock\Server\Shared\Sessions\SessionEnded;
use Lock\Server\Shared\Sessions\Sessions;

class SessionsServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->tag([OidcSession::class], 'oidc.prunable');

        $this->app->singleton(SessionTokenProvider::class, SessionTokenIssuer::class);
        $this->app->singleton(OidcSessionRepository::class);
        $this->app->bind(Sessions::class, OidcSessionRepository::class);
        $this->app->bind(SessionContext::class, OidcSessionState::class);
        $this->app->singleton(BackChannelLogoutNotifier::class);
    }

    public function boot(): void
    {
        Event::listen(UserDeleting::class, DeleteUserData::class);
        Event::listen(RealmDeleting::class, DeleteRealmData::class);

        Event::listen(SessionEnded::class, BackChannelLogoutNotifier::class);
        Event::listen(Login::class, EstablishSessionToken::class);
        Event::listen(Login::class, StartOidcSession::class);
        Event::listen(Logout::class, ForgetSessionToken::class);
        Event::listen(Logout::class, EndOidcSession::class);

        if ($this->app->runningInConsole()) {
            $this->commands([DispatchExpiredSessionLogoutsCommand::class]);
        }
    }
}
