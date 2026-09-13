<?php

declare(strict_types=1);

namespace Lock\Server\Credentials;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Recovery codes cover all factor types and exist only while a confirmed factor remains.
 */
class EnrollmentPolicy
{
    public function __construct(
        private readonly FactorRegistry $factors,
        private readonly RecoveryCodeProvider $recoveryCodes,
    ) {}

    /**
     * True means fresh recovery codes must be shown to the user.
     */
    public function factorConfirmed(Authenticatable $user): bool
    {
        if ($this->recoveryCodes->enrollments($user) === []) {
            $this->recoveryCodes->generate($user);

            return true;
        }

        return false;
    }

    public function factorRevoked(Authenticatable $user): void
    {
        if ($this->factors->challengeableEnrollments($user) === []) {
            $this->recoveryCodes->clear($user);
        }
    }
}
