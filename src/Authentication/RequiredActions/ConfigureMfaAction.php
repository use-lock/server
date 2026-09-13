<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\RequiredActions;

use Illuminate\Contracts\Auth\Authenticatable;
use Lock\Server\Authentication\Contracts\RequiredAction;
use Lock\Server\Shared\Credentials\FactorRegistry;
use Lock\Server\Shared\Realms\Realm;
use Lock\Server\Shared\Realms\Settings\MfaRequirement;

/**
 * The consumer of MfaRequirement::Always: a user the realm insists on a
 * second factor for, who has none, is walked through enrollment instead of
 * being turned away. It stops reporting the moment a factor is confirmed,
 * and it never reports for a realm with nothing to enroll — there the demand
 * is unsatisfiable and the login sequence denies it outright.
 */
readonly class ConfigureMfaAction implements RequiredAction
{
    public function __construct(private FactorRegistry $factors) {}

    public function key(): string
    {
        return 'configure_mfa';
    }

    public function isPending(Authenticatable $user, Realm $realm): bool
    {
        return $realm->authentication()->mfa === MfaRequirement::Always
            && $this->factors->configuredChallengeableEnrollments($user) === []
            && $this->factors->enrollmentOptions() !== [];
    }

    public function route(): string
    {
        return 'identity.two-factor.setup';
    }
}
