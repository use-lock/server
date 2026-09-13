<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Credentials;

use Illuminate\Contracts\Auth\Authenticatable;

interface FactorProvider
{
    public function key(): string;

    public function isBackup(): bool;

    /**
     * @return list<FactorEnrollment>
     */
    public function enrollments(Authenticatable $user): array;

    public function beginChallenge(Authenticatable $user, FactorEnrollment $enrollment): FactorChallenge;

    /**
     * @param  array<string, mixed>  $input
     */
    public function verify(Authenticatable $user, FactorChallenge $challenge, array $input): FactorVerification;
}
