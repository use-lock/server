<?php

declare(strict_types=1);

namespace Lock\Server\Sessions\Listeners;

use Lock\Server\Sessions\Models\OidcSession;
use Lock\Server\Shared\Maintenance\RealmDeleting;

final class DeleteRealmData
{
    public function handle(RealmDeleting $event): void
    {
        OidcSession::query()->where('realm', $event->realm())->delete();
    }
}
