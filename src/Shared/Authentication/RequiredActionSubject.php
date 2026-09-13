<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Authentication;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;

interface RequiredActionSubject
{
    public function current(Request $request): ?Authenticatable;
}
