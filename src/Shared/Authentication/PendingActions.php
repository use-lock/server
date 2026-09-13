<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Authentication;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * What the login sequence and the authorization endpoint need to know about
 * required actions: what is still open for a user, where to send them, and
 * that one is done.
 */
interface PendingActions
{
    /**
     * The keys still open for this user, in registration order.
     *
     * @return list<string>
     */
    public function for(Authenticatable $user): array;

    /** The URL of the first open action, or null when nothing is open. */
    public function url(Authenticatable $user): ?string;

    /**
     * Marks an action done. A derived action stops reporting on its own once
     * the state behind it changes; this additionally clears an action the
     * post-login pipeline asked for, which has no state of its own to change.
     */
    public function complete(Authenticatable $user, string $key): void;
}
