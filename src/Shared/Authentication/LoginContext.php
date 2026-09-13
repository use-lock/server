<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Authentication;

interface LoginContext
{
    public function snapshot(): LoginSnapshot;
}
