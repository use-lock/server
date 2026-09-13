<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Credentials;

use Illuminate\Contracts\Auth\Authenticatable;

interface FactorRegistry
{
    public function get(string $key): FactorProvider;

    public function enrollable(string $key): ?EnrollableFactorProvider;

    /** @return list<EnrollmentOption> */
    public function enrollmentOptions(): array;

    public function enrollmentOption(string $id): ?EnrollmentOption;

    /**
     * @return list<FactorEnrollment>
     */
    public function enrollments(Authenticatable $user): array;

    public function findEnrollment(Authenticatable $user, string $providerKey, string $id): ?FactorEnrollment;

    /** @return list<FactorEnrollment> */
    public function configuredChallengeableEnrollments(Authenticatable $user): array;
}
