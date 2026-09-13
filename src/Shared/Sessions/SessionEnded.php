<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Sessions;

use Illuminate\Contracts\Events\ShouldDispatchAfterCommit;

final readonly class SessionEnded implements ShouldDispatchAfterCommit
{
    public function __construct(public string $sid, public string $realm) {}
}
