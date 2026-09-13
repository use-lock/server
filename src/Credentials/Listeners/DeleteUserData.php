<?php

declare(strict_types=1);

namespace Lock\Server\Credentials\Listeners;

use Lock\Server\Credentials\Models\PasswordHistory;
use Lock\Server\Credentials\Models\RecoveryCode;
use Lock\Server\Credentials\Models\TotpFactor;
use Lock\Server\Shared\Maintenance\UserDeleting;

final class DeleteUserData
{
    public function handle(UserDeleting $event): void
    {
        PasswordHistory::query()->where('user_id', (string) $event->user()->getAuthIdentifier())->delete();
        TotpFactor::query()->where('user_id', (string) $event->user()->getAuthIdentifier())->delete();
        RecoveryCode::query()->where('user_id', (string) $event->user()->getAuthIdentifier())->delete();
    }
}
