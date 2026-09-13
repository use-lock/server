<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Scopes;

use Illuminate\Support\Collection;
use Lock\Server\Shared\Clients\Client;

/**
 * Every lookup is bound to the resources the request asks for: a scope only
 * exists under the audiences that own it. An empty `$audiences` means the
 * realm's default audience, its issuer URL — the same convention the token
 * minter follows.
 */
interface ScopeRepository
{
    /**
     * @param  list<string>  $audiences
     * @return Collection<int, Scope>
     */
    public function all(array $audiences = []): Collection;

    /** @param  list<string>  $audiences */
    public function find(string $identifier, array $audiences = []): ?Scope;

    /**
     * @param  list<string>  $requested
     * @param  list<string>  $audiences
     * @return list<string>
     */
    public function grant(array $requested, string $grantType, ?Client $client, ?string $userIdentifier = null, array $audiences = []): array;
}
