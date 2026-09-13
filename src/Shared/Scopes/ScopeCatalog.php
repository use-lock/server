<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Scopes;

interface ScopeCatalog
{
    /**
     * The scopes the given resources own. A scope belongs to exactly one
     * resource, so the same value may mean different things under different
     * audiences; the realm itself is named by its issuer URL and owns the
     * scopes that belong to no registered resource.
     *
     * @param  list<string>  $audiences  resolved RFC 8707 resource identifiers, never empty
     * @return array<string, string> scope id => description
     */
    public function scopes(array $audiences): array;
}
