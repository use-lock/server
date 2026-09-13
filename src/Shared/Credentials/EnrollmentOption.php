<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Credentials;

final readonly class EnrollmentOption
{
    /**
     * @param  string  $id  Globally unique across providers; the value a setup surface submits.
     * @param  array<string, mixed>  $hints  Provider-specific enrollment parameters.
     */
    public function __construct(
        public string $id,
        public string $providerKey,
        public FactorRole $role,
        public FactorSetupKind $setupKind,
        public bool $recommended = false,
        public int $sortOrder = 0,
        public array $hints = [],
    ) {}
}
