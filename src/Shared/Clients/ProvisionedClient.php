<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Clients;

final readonly class ProvisionedClient
{
    public function __construct(
        public Client $client,
        public ?string $clientSecret,
        public bool $wasCreated,
        public bool $secretRotated,
    ) {}
}
