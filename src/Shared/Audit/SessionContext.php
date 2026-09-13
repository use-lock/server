<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Audit;

interface SessionContext
{
    public function sid(): ?string;
}
