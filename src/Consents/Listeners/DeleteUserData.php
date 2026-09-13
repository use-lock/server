<?php

declare(strict_types=1);

namespace Lock\Server\Consents\Listeners;

use Lock\Server\Consents\Models\Consent;
use Lock\Server\Shared\Maintenance\UserDeleting;

final class DeleteUserData
{
    public function handle(UserDeleting $event): void
    {
        Consent::query()->where('user_id', (string) $event->user()->getAuthIdentifier())->delete();
    }
}
