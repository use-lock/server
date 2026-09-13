<?php

declare(strict_types=1);

namespace Lock\Server\SigningKeys;

final readonly class GeneratedSigningKeys
{
    public function __construct(
        public string $privateKeyPem,
        public string $publicKeyPem,
        public string $kid,
    ) {}
}
