<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\Listeners;

use Lock\Server\Authentication\Models\PasswordResetToken;
use Lock\Server\Shared\Maintenance\RealmDeleting;

final class DeleteRealmData
{
    public function handle(RealmDeleting $event): void
    {
        PasswordResetToken::query()->where('realm', $event->realm())->delete();
    }
}
