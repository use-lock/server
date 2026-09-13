<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Sessions;

use Carbon\CarbonInterface;

final readonly class SessionSnapshot
{
    public function __construct(
        public string $realm,
        public ?string $sid,
        public ?int $authTime,
        public ?CarbonInterface $expiresAt,
        public bool $active,
    ) {}
}
