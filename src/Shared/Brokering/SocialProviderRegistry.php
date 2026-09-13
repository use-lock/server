<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Brokering;

interface SocialProviderRegistry
{
    public function get(string $key): ?SocialProvider;

    /** @return array<string, SocialProvider> */
    public function enabled(): array;
}
