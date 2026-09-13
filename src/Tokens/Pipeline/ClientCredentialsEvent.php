<?php

declare(strict_types=1);

namespace Lock\Server\Tokens\Pipeline;

use Lock\Server\Shared\Clients\Client;

final readonly class ClientCredentialsEvent
{
    /**
     * @param  list<string>  $scopes
     * @param  list<string>  $audiences  RFC 8707 `resource` values the token will be bound to
     */
    public function __construct(
        public Client $client,
        public array $scopes,
        public array $audiences = [],
    ) {}
}
