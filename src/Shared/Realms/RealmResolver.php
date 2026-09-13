<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Realms;

/**
 * Singleton implementations must resolve the current request on every call:
 * Octane reuses the same instance across requests.
 */
interface RealmResolver
{
    public function current(): Realm;
}
