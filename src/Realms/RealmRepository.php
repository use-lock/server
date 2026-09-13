<?php

declare(strict_types=1);

namespace Lock\Server\Realms;

use Lock\Server\Shared\Realms\Realm;

/**
 * Looks a realm up by the identifier in the request path, or by the host it
 * is served from in `domain` routing. An application with a realm model binds
 * its own implementation; an unknown identifier or host returns null and the
 * request answers 404.
 */
interface RealmRepository
{
    public function find(string $id): ?Realm;

    /** @param string $host the request host, without scheme or port */
    public function findByDomain(string $host): ?Realm;
}
