<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Credentials;

use Illuminate\Contracts\Auth\Authenticatable;

interface FactorOperations
{
    public function enroll(
        Authenticatable $user,
        EnrollableFactorProvider $provider,
        ?EnrollmentOption $option = null,
        ?string $name = null,
    ): FactorEnrollment;

    /**
     * @param  array<string, mixed>  $proof
     */
    public function confirm(
        Authenticatable $user,
        EnrollableFactorProvider $provider,
        FactorEnrollment $enrollment,
        array $proof,
    ): bool;

    public function revoke(Authenticatable $user, EnrollableFactorProvider $provider, FactorEnrollment $enrollment): void;

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
    ): ?FactorVerification;
}
