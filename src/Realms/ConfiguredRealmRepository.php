<?php

declare(strict_types=1);

namespace Lock\Server\Realms;

use Lock\Server\Shared\Realms\Realm;

/**
 * Accepts every realm identifier and serves it with the configured
 * settings — realms differ only by their id, as in a deployment that
 * scopes data per tenant but configures all tenants alike. In `domain`
 * routing the host is mapped through `oidc.routes.domains`; an app with a
 * realm model binds its own repository and resolves from its own column.
 */
final class ConfiguredRealmRepository implements RealmRepository
{
    public function find(string $id): ?Realm
    {
        return $id === '' ? null : new ConfiguredRealm($id);
    }

    public function findByDomain(string $host): ?Realm
    {
        $id = ((array) config('oidc.routes.domains', []))[$host] ?? null;

        return is_string($id) ? $this->find($id) : null;
    }
}
