<?php

declare(strict_types=1);

namespace Lock\Server\Realms;

use Lock\Server\Shared\Realms\CurrentRealm;
use Lock\Server\Shared\Realms\Realm;
use Lock\Server\Shared\Realms\RealmResolver;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

/**
 * Derives the realm from the request: from the attribute ResolveRealm sets, or
 * from the `{realm}` route parameter before it has run. Console commands,
 * queue jobs and anything else outside a matched route fall back to the
 * configured realm. A path naming a realm the repository does not know is a
 * 404.
 */
final readonly class RouteRealmResolver implements RealmResolver
{
    public function __construct(
        private RealmRepository $realms,
        private RealmResolver $fallback,
    ) {}

    public function current(): Realm
    {
        $request = request();
        $id = $request->attributes->get(CurrentRealm::ATTRIBUTE) ?? $request->route('realm');

        if (! is_string($id) || $id === '') {
            return $this->fallback->current();
        }

        return $this->realms->find($id) ?? throw new NotFoundHttpException("Unknown realm [{$id}].");
    }
}
