<?php

declare(strict_types=1);

namespace Lock\Server\Scopes;

use Lock\Server\Shared\Clients\Client;
use Lock\Server\Shared\Scopes\Scope;
use Lock\Server\Shared\Scopes\ScopeParameterPolicy;

/**
 * Without a host policy, only a value an administrator assigned to the client
 * verbatim is granted; any value a client merely requests is refused.
 */
final readonly class AssignedScopeParameterPolicy implements ScopeParameterPolicy
{
    public function allows(Scope $scope, string $grantType, ?Client $client, ?string $userIdentifier, array $audiences): bool
    {
        return $client instanceof Client && in_array($scope->id, $client->assignedScopes($audiences), true);
    }
}
