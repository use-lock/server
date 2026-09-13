<?php

declare(strict_types=1);

namespace Lock\Server\SigningKeys\Listeners;

use Lock\Server\Shared\Maintenance\RealmDeleting;
use Lock\Server\SigningKeys\Models\SigningKey;

final class DeleteRealmData
{
    public function handle(RealmDeleting $event): void
    {
        SigningKey::query()->where('realm', $event->realm())->delete();
    }
}
