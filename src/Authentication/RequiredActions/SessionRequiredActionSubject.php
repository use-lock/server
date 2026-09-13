<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\RequiredActions;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Lock\Server\Authentication\Concerns\ResolvesIdentityGuard;
use Lock\Server\Shared\Authentication\RequiredActionSubject;

/**
 * Who an action screen is acting for. A required action is reached from two
 * directions: mid-login, when no session exists yet and only the pending
 * record names the user, and from a live session whose state has since
 * drifted into an open action. Both resolve here so the screens themselves
 * stay unaware of which one they are serving.
 */
final readonly class SessionRequiredActionSubject implements RequiredActionSubject
{
    use ResolvesIdentityGuard;

    public function current(Request $request): ?Authenticatable
    {
        $user = $this->currentUser($request);

        if ($user instanceof Authenticatable) {
            return $user;
        }

        $pending = PendingRequiredActions::find();

        return $pending instanceof PendingRequiredActions
            ? $this->sessionGuard()->getProvider()->retrieveById($pending->userId)
            : null;
    }
}
