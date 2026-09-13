<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Credentials;

use Illuminate\Contracts\Auth\Authenticatable;

interface EnrollableFactorProvider extends FactorProvider
{
    /** @return list<EnrollmentOption> */
    public function enrollmentOptions(): array;

    /**
     * $option is the entry from {@see self::enrollmentOptions()} the
     * user picked; null falls back to the provider's own default.
     */
    public function beginEnrollment(Authenticatable $user, ?EnrollmentOption $option = null, ?string $name = null): FactorEnrollment;

    /**
     * @param  array<string, mixed>  $input
     */
    public function confirmEnrollment(Authenticatable $user, FactorEnrollment $enrollment, array $input): bool;

    public function revoke(Authenticatable $user, FactorEnrollment $enrollment): void;
}
