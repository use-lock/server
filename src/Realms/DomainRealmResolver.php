<?php

declare(strict_types=1);

namespace Lock\Server\Realms;

use Lock\Server\Shared\Realms\CurrentRealm;
use Lock\Server\Shared\Realms\Realm;
use Lock\Server\Shared\Realms\RealmResolver;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

/**
 * Derives the realm from the host the request came in on, so every realm is
 * its own origin and every endpoint keeps its canonical path. A host the
 * repository does not know is a 404.
 *
 * A queued job is the exception: its worker's request is built from `app.url`
 * rather than received, so its host names whichever realm that URL points at
 * instead of the one the job was queued from. ResolveRealmForJob records the
 * job's realm the way the middleware records a request's, and that reading
 * wins over the host. Console commands have no host at all and fall back to
 * the configured realm.
 *
 * The host comes from the request, so the application must be configured to
 * trust it (Laravel's TrustHosts and TrustProxies middleware); an untrusted
 * Host header would otherwise choose the realm.
 */
final readonly class DomainRealmResolver implements RealmResolver
{
    public function __construct(
        private RealmRepository $realms,
        private RealmResolver $fallback,
    ) {}

    public function current(): Realm
    {
        $request = request();
        $resolved = $request->attributes->get(CurrentRealm::ATTRIBUTE);

        if (is_string($resolved) && $resolved !== '') {
            return $this->realms->find($resolved) ?? throw new NotFoundHttpException("Unknown realm [{$resolved}].");
        }

        $host = $request->getHost();

        if ($host === '') {
            return $this->fallback->current();
        }

        return $this->realms->findByDomain($host) ?? throw new NotFoundHttpException("No realm is served from [{$host}].");
    }
}
