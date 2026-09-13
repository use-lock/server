<?php

declare(strict_types=1);

namespace Lock\Server\Tokens\Exchange;

use Lock\Server\Shared\Clients\Client;

final readonly class ExchangeRequest
{
    /**
     * @param  array<string, mixed>  $subjectClaims
     * @param  string[]|null  $requestedScopes
     * @param  array<string, mixed>  $parameters
     */
    public function __construct(
        public Client $client,
        public array $subjectClaims,
        public ?string $requestedAudience,
        public ?array $requestedScopes,
        public int $subjectExpiresAt,
        public array $parameters = [],
    ) {}
}
