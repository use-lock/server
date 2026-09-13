<?php

declare(strict_types=1);

namespace Lock\Server\Realms;

use Lock\Server\Shared\Context\OidcContext;
use Lock\Server\Shared\Realms\Realm;
use Lock\Server\Shared\Realms\RealmResolver;

/**
 * Single-realm default, and what the routed resolvers fall back to when there
 * is no request to read a realm from. The context comes first: a queued job
 * carries the realm it was dispatched from, and honouring it here is what
 * keeps realm-scoped queries, issuers and signing keys correct on the worker.
 */
final readonly class ConfiguredRealmResolver implements RealmResolver
{
    public function __construct(private RealmRepository $realms) {}

    public function current(): Realm
    {
        $id = OidcContext::realm() ?? (string) config('oidc.realm', 'default');

        if ($id === '') {
            $id = 'default';
        }

        return $this->realms->find($id) ?? new ConfiguredRealm($id);
    }
}
