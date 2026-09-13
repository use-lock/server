<?php

declare(strict_types=1);

namespace Lock\Server\Tokens\Pipeline;

use Lock\Server\Shared\Authentication\RealmUser;
use Lock\Server\Shared\Clients\Client;

final readonly class DirectAccessTokenEvent
{
    /**
     * @param  list<string>  $scopes
     * @param  array<string, mixed>  $context
     */
    public function __construct(
        public RealmUser $user,
        public Client $client,
        public array $scopes,
        public array $context = [],
    ) {}
}
