<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Clients;

final readonly class RegisteredClient
{
    public function __construct(
        public Client $client,
        public ?string $issuedSecret,
    ) {}
}
