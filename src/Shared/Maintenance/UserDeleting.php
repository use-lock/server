<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Maintenance;

use Illuminate\Contracts\Auth\Authenticatable;

interface UserDeleting
{
    public function user(): Authenticatable;
}
