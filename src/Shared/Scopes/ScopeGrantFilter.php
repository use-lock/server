<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Scopes;

use Lock\Server\Shared\Clients\Client;

/**
 * Narrows the scopes a token is issued with to what its subject may hold, e.g.
 * the permissions a user's roles grant within the organization named by
 * `organization:{organization}`. It sees the whole set, because a scope may
 * depend on another one granted alongside it. Runs on every grant, refresh
 * included, and can only take scopes away: anything it adds is ignored.
 */
interface ScopeGrantFilter
{
    /**
     * @param  list<Scope>  $scopes
     * @param  list<string>  $audiences
     * @return list<Scope>
     */
    public function filter(array $scopes, string $grantType, ?Client $client, ?string $userIdentifier, array $audiences): array;
}
