<?php

declare(strict_types=1);

namespace Lock\Server\Sessions\Listeners;

use Lock\Server\Sessions\Models\OidcSession;
use Lock\Server\Shared\Maintenance\UserDeleting;

final class DeleteUserData
{
    public function handle(UserDeleting $event): void
    {
        OidcSession::query()->where('user_id', (string) $event->user()->getAuthIdentifier())->delete();
    }
}
