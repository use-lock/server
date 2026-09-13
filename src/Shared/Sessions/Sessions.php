<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Sessions;

use Illuminate\Contracts\Session\Session;

interface Sessions
{
    public function current(): SessionSnapshot;

    public function get(string $sid): ?SessionSnapshot;

    public function recordParticipant(string $sid, string $clientKey): void;

    public function end(?Session $session = null): void;
}
