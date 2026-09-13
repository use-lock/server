<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Maintenance;

interface RealmDeleting
{
    public function realm(): string;
}
