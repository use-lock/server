<?php

declare(strict_types=1);

namespace Lock\Server\Clients\Listeners;

use Lock\Server\Clients\Models\Client;
use Lock\Server\Shared\Maintenance\RealmDeleting;

final class DeleteRealmData
{
    public function handle(RealmDeleting $event): void
    {
        Client::query()->where('realm', $event->realm())->delete();
    }
}
