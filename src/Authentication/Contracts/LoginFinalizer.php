<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Lock\Server\Authentication\LoginOutcome;

/**
 * The single post-authentication sequence every interactive login must pass
 * through: post-login policy, claim buffering, second-factor gating, guard
 * login. Calling guard->login() directly bypasses the policy and leaves the
 * authentication methods untracked.
 */
interface LoginFinalizer
{
    /**
     * $challengeEnrolledFactors controls whether an enrolled second factor is
     * challenged automatically; a login method that already verified the
     * device (passkeys) passes false. An explicit requireMfa() from the
     * pipeline still forces the challenge.
     */
    public function finalize(
        Request $request,
        Authenticatable $user,
        string $method,
        bool $remember = false,
        bool $challengeEnrolledFactors = true,
    ): LoginOutcome;

    /**
     * The tail of the ceremony for a flow that finished its own verification
     * afterwards — a second-factor challenge, a required-action screen. It
     * checks what the realm still requires of the user and either parks the
     * login on the next action or completes it.
     */
    public function finish(Request $request, Authenticatable $user, bool $remember = false): LoginOutcome;

    /**
     * The last step: guard login, session regeneration and the LoginSucceeded
     * event. Call finish() instead unless the required actions have already
     * been settled — this one asks the realm nothing.
     */
    public function complete(Request $request, Authenticatable $user, bool $remember = false): void;
}
