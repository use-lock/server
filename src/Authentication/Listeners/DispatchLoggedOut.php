<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\Listeners;

use Illuminate\Auth\Events\Logout;
use Lock\Server\Authentication\Events\LoggedOut;
use Lock\Server\Shared\Authentication\IdentityGuard;

final readonly class DispatchLoggedOut
{
    public function handle(Logout $event): void
    {
        if ($event->guard !== IdentityGuard::name() || $event->user === null) {
            return;
        }

        event(new LoggedOut((string) $event->user->getAuthIdentifier()));
    }
}
