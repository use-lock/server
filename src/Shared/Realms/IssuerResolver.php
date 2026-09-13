<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Realms;

interface IssuerResolver
{
    public function url(): string;
}
