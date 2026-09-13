<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Lock\Server\Shared\Realms\Realm;

/**
 * Something the realm insists a user does before the login completes.
 *
 * Pendency is derived, never stored: an action reads the state that makes it
 * necessary and stops reporting once that state changes. There is no row to
 * go stale, and a realm that turns a rule on sees it apply to users who
 * registered long before. An application adds its own action by registering
 * an implementation whose isPending() reads its own state — an unaccepted
 * terms version, an incomplete profile.
 */
interface RequiredAction
{
    /** Stable identifier; it appears in the JSON login response and in audit records. */
    public function key(): string;

    /**
     * Whether this user still has to do it. Called on every login and on
     * every authorization request, so it must be cheap and must not assume a
     * session exists — a throwing implementation denies the login, because a
     * user who never reaches the end of the ceremony never gets a session.
     */
    public function isPending(Authenticatable $user, Realm $realm): bool;

    /** Name of the route that lets the user do it. */
    public function route(): string;
}
