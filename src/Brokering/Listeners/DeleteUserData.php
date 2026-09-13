<?php

declare(strict_types=1);

namespace Lock\Server\Brokering\Listeners;

use Lock\Server\Brokering\Models\SocialAccount;
use Lock\Server\Shared\Maintenance\UserDeleting;

final class DeleteUserData
{
    public function handle(UserDeleting $event): void
    {
        SocialAccount::query()->where('user_id', (string) $event->user()->getAuthIdentifier())->delete();
    }
}
