<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Credentials;

final readonly class FactorChallenge
{
    /**
     * @param  array<string, mixed>  $publicData
     * @param  array<string, mixed>  $privateState
     */
    public function __construct(
        public FactorEnrollment $enrollment,
        public array $publicData = [],
        public array $privateState = [],
    ) {}
}
