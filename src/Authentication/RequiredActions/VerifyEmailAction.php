<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\RequiredActions;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Lock\Server\Authentication\Contracts\RequiredAction;
use Lock\Server\Shared\Realms\Realm;

/**
 * A user model that does not implement MustVerifyEmail has no address to
 * confirm, so the realm's requirement cannot apply to it.
 */
final readonly class VerifyEmailAction implements RequiredAction
{
    public function key(): string
    {
        return 'verify_email';
    }

    public function isPending(Authenticatable $user, Realm $realm): bool
    {
        return $realm->authentication()->emailVerificationRequired
            && $user instanceof MustVerifyEmail
            && ! $user->hasVerifiedEmail();
    }

    public function route(): string
    {
        return 'identity.verification.notice';
    }
}
