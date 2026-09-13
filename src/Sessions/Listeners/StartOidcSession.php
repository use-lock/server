<?php

declare(strict_types=1);

namespace Lock\Server\Sessions\Listeners;

use Illuminate\Auth\Events\Login;
use Lock\Server\Sessions\OidcSessionRepository;
use Lock\Server\Sessions\OidcSessionState;
use Lock\Server\Shared\Authentication\IdentityGuard;

class StartOidcSession
{
    public function __construct(
        private readonly OidcSessionRepository $registry,
        private readonly OidcSessionState $sessionState,
    ) {}

    public function handle(Login $event): void
    {
        if ($event->guard !== IdentityGuard::name()) {
            return;
        }

        $browserSession = app()->bound('session.store') ? app('session.store') : null;

        $sid = $this->registry->start(
            (string) $event->user->getAuthIdentifier(),
            $browserSession?->isStarted() ? $browserSession->getId() : null,
        );

        if ($browserSession !== null) {
            $this->sessionState->startOidcSession($sid);
        }
    }
}
