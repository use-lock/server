<?php

declare(strict_types=1);

namespace Lock\Server\Tokens\Listeners;

use Lock\Server\Shared\Maintenance\RealmDeleting;
use Lock\Server\Tokens\Models\AuthenticationContext;

final class DeleteRealmData
{
    public function handle(RealmDeleting $event): void
    {
        AuthenticationContext::query()->where('realm', $event->realm())->delete();
    }
}
