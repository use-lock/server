<?php

declare(strict_types=1);

namespace Lock\Server\Realms;

use Illuminate\Support\Facades\URL;
use Lock\Server\Shared\Context\OidcContext;
use Lock\Server\Shared\Realms\CurrentRealm;
use Lock\Server\Shared\Realms\RealmResolver;

/**
 * The realm comes from the context, which Laravel restored from the job's
 * payload a moment earlier — this runs after the framework's own
 * JobProcessing listener because the package boots after it. It is recorded
 * on the request the same way the middleware records it, because a worker's
 * request is not an inbound one: it is built from `app.url`, so its host
 * would otherwise name whichever realm that URL happens to point at.
 */
final readonly class ResolveRealmForJob
{
    public function __construct(private RealmResolver $realms) {}

    public function __invoke(): void
    {
        $realm = OidcContext::realm();
        $attributes = request()->attributes;

        $realm === null
            ? $attributes->remove(CurrentRealm::ATTRIBUTE)
            : $attributes->set(CurrentRealm::ATTRIBUTE, $realm);

        URL::defaults(['realm' => $this->realms->current()->identifier()]);
    }
}
