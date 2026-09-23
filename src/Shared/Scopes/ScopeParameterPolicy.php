<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Scopes;

use Lock\Server\Shared\Clients\Client;

/**
 * Decides at issuance whether a token may carry a parameterized scope with its
 * value, e.g. whether the user belongs to the organization in
 * `organization:{organization}`. A scope the policy refuses is dropped.
 */
interface ScopeParameterPolicy
{
    /** @param  list<string>  $audiences */
    public function allows(Scope $scope, string $grantType, ?Client $client, ?string $userIdentifier, array $audiences): bool;
}
