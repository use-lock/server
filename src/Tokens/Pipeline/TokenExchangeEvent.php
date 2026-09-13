<?php

declare(strict_types=1);

namespace Lock\Server\Tokens\Pipeline;

use Illuminate\Contracts\Auth\Authenticatable;
use Lock\Server\Shared\Clients\Client;

final readonly class TokenExchangeEvent
{
    /**
     * @param  list<string>  $scopes
     * @param  array<string, mixed>  $subjectClaims
     */
    public function __construct(
        public Authenticatable $user,
        public Client $client,
        public array $scopes,
        public string $audience,
        public array $subjectClaims,
    ) {}
}
