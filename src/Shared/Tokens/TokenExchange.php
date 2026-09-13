<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Tokens;

use DateInterval;
use Lock\Server\Shared\Clients\Client;

interface TokenExchange
{
    /**
     * @param  list<string>|null  $scopes
     * @param  array<string, mixed>  $parameters
     */
    public function exchange(string $subjectToken, Client $requestingClient, string $audience, ?array $scopes = null, ?DateInterval $accessTokenTTL = null, array $parameters = []): MintedAccessToken;
}
