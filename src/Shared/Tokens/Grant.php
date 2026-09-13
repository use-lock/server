<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Tokens;

use Lock\Server\Shared\Clients\Client;

/**
 * The endpoint authenticates the client and checks grant eligibility before invocation.
 */
interface Grant
{
    public function type(): string;

    public function handle(Client $client, GrantRequest $request): TokenSet;
}
