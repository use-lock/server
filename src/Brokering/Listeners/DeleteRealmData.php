<?php

declare(strict_types=1);

namespace Lock\Server\Brokering\Listeners;

use Lock\Server\Brokering\Models\SocialAccount;
use Lock\Server\Shared\Maintenance\RealmDeleting;

final class DeleteRealmData
{
    public function handle(RealmDeleting $event): void
    {
        SocialAccount::query()->where('realm', $event->realm())->delete();
    }
}
