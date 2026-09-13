<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\Listeners;

use Lock\Server\Authentication\Models\PasswordResetToken;
use Lock\Server\Shared\Maintenance\UserDeleting;

final class DeleteUserData
{
    public function handle(UserDeleting $event): void
    {
        PasswordResetToken::query()->where('user_id', (string) $event->user()->getAuthIdentifier())->delete();
    }
}
