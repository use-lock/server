<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Clients;

interface RegisterClient
{
    /** @param array<string, mixed> $metadata */
    public function __invoke(array $metadata): RegisteredClient;
}
