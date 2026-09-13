<?php

declare(strict_types=1);

namespace Lock\Server\Sessions\Listeners;

use Illuminate\Auth\Events\Logout;
use Lock\Server\Sessions\OidcSessionRepository;
use Lock\Server\Sessions\OidcSessionState;
use Lock\Server\Shared\Authentication\IdentityGuard;

class EndOidcSession
{
    public function __construct(
        private readonly OidcSessionRepository $registry,
        private readonly OidcSessionState $sessionState,
    ) {}

    public function handle(Logout $event): void
    {
        if ($event->guard !== IdentityGuard::name()) {
            return;
        }

        if (! app()->bound('session.store') || ! app('session.store')->isStarted()) {
            return;
        }

        $sid = $this->sessionState->sid();
        if ($sid === null) {
            return;
        }

        $this->registry->revoke($sid);
    }
}
