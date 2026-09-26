<?php

declare(strict_types=1);

namespace Lock\Server\Scopes;

use Lock\Server\Shared\Clients\Client;
use Lock\Server\Shared\Scopes\ScopeGrantFilter;

final readonly class UnfilteredScopeGrant implements ScopeGrantFilter
{
    public function filter(array $scopes, string $grantType, ?Client $client, ?string $userIdentifier, array $audiences): array
    {
        return $scopes;
    }
}
