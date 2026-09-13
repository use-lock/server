<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * What the login sequence needs to know about second factors: whether the
 * user can be challenged at all, and how to park the login until they are.
 */
interface SecondFactorGate
{
    public function hasChallengeableFactors(Authenticatable $user): bool;

    /**
     * Whether this user could enroll a factor at all. A realm that insists on
     * a second factor sends a user without one to enrollment; if there is
     * nothing to enroll, the demand cannot be met and the login is denied
     * rather than looping on a screen with no options.
     */
    public function canEnrollFactor(Authenticatable $user): bool;

    /**
     * Stores the pending challenge for the current session; the challenge
     * endpoints complete the login once the factor is verified.
     */
    public function beginChallenge(Authenticatable $user, bool $remember): void;
}
