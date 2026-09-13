<?php

declare(strict_types=1);

namespace Lock\Server\Credentials;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Lock\Server\Credentials\Events\FactorConfirmed;
use Lock\Server\Credentials\Events\FactorEnrollmentStarted;
use Lock\Server\Credentials\Events\FactorRevoked;
use Lock\Server\Credentials\Events\MfaChallengeFailed;
use Lock\Server\Credentials\Events\MfaChallengeSucceeded;
use Lock\Server\Credentials\Events\RecoveryCodeUsed;
use Lock\Server\Shared\Credentials\EnrollableFactorProvider;
use Lock\Server\Shared\Credentials\EnrollmentOption;
use Lock\Server\Shared\Credentials\FactorChallenge;
use Lock\Server\Shared\Credentials\FactorEnrollment;
use Lock\Server\Shared\Credentials\FactorOperations as FactorOperationsContract;
use Lock\Server\Shared\Credentials\FactorVerification;
use Lock\Server\Shared\Realms\RealmResolver;

readonly class FactorOperations implements FactorOperationsContract
{
    public function __construct(
        private FactorRegistry $factors,
        private EnrollmentPolicy $policy,
        private RealmResolver $realms,
    ) {}

    public function enroll(
        Authenticatable $user,
        EnrollableFactorProvider $provider,
        ?EnrollmentOption $option = null,
        ?string $name = null,
    ): FactorEnrollment {
        $enrollment = $provider->beginEnrollment($user, $option, $name);

        event(new FactorEnrollmentStarted((string) $user->getAuthIdentifier(), $provider->key(), $enrollment->id, $this->realms->current()->identifier()));

        return $enrollment;
    }

    /**
     * @param  array<string, mixed>  $proof
     */
    public function confirm(
        Authenticatable $user,
        EnrollableFactorProvider $provider,
        FactorEnrollment $enrollment,
        array $proof,
    ): bool {
        return DB::transaction(function () use ($user, $provider, $enrollment, $proof): bool {
            if (! $provider->confirmEnrollment($user, $enrollment, $proof)) {
                return false;
            }

            $this->policy->factorConfirmed($user);

            event(new FactorConfirmed((string) $user->getAuthIdentifier(), $provider->key(), $enrollment->id, $this->realms->current()->identifier()));

            return true;
        });
    }

    public function revoke(Authenticatable $user, EnrollableFactorProvider $provider, FactorEnrollment $enrollment): void
    {
        DB::transaction(function () use ($user, $provider, $enrollment): void {
            $provider->revoke($user, $enrollment);
            $this->policy->factorRevoked($user);

            event(new FactorRevoked((string) $user->getAuthIdentifier(), $provider->key(), $enrollment->id, $this->realms->current()->identifier()));
        });
    }

    /**
     * @param  array<string, mixed>  $proof  `code`, `recovery_code`, or `credential`
     * @param  array<string, mixed>  $privateState
     */
    public function verify(
        Authenticatable $user,
        string $factor,
        string $factorId,
        array $proof,
        array $privateState,
    ): ?FactorVerification {
        $usesRecoveryCode = isset($proof['recovery_code']) && $proof['recovery_code'] !== '';
        $providerKey = $usesRecoveryCode ? 'recovery_code' : $factor;
        $provider = $this->factors->get($providerKey);
        $enrollment = $usesRecoveryCode
            ? $provider->enrollments($user)[0] ?? null
            : $this->pendingEnrollment($user, $providerKey, $factorId);

        if (! $enrollment instanceof FactorEnrollment) {
            event(new MfaChallengeFailed((string) $user->getAuthIdentifier(), $providerKey, 'unknown_enrollment'));

            return null;
        }

        $challenge = new FactorChallenge($enrollment, privateState: $privateState);
        $verification = $provider->verify($user, $challenge, $proof);

        if (! $verification->verified) {
            event(new MfaChallengeFailed((string) $user->getAuthIdentifier(), $providerKey, 'invalid_code'));

            return null;
        }

        event(new MfaChallengeSucceeded((string) $user->getAuthIdentifier(), $providerKey));

        if ($usesRecoveryCode) {
            event(new RecoveryCodeUsed((string) $user->getAuthIdentifier(), $this->realms->current()->identifier()));
        }

        return $verification;
    }

    protected function pendingEnrollment(Authenticatable $user, string $providerKey, string $id): ?FactorEnrollment
    {
        foreach ($this->factors->get($providerKey)->enrollments($user) as $enrollment) {
            if ($id === '' || $enrollment->id === $id) {
                return $enrollment;
            }
        }

        return null;
    }
}
