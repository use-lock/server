<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Credentials;

use DateTimeInterface;

final readonly class FactorEnrollment
{
    /**
     * @param  array<string, mixed>  $metadata
     */
    public function __construct(
        public string $providerKey,
        public string $id,
        public string $label,
        public ?DateTimeInterface $confirmedAt,
        public ?DateTimeInterface $lastUsedAt,
        public array $metadata = [],
    ) {}
}
