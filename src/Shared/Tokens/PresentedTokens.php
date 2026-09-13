<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Tokens;

use Lock\Server\Shared\Clients\Client;

interface PresentedTokens
{
    /** @return array<string, mixed> */
    public function introspect(Client $client, string $value, ?string $hint = null): array;

    public function revoke(Client $client, string $value, ?string $hint = null): void;
}
