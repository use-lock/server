<?php

declare(strict_types=1);

namespace Lock\Server\Credentials;

use Illuminate\Contracts\Auth\Authenticatable;
use Lock\Server\Shared\Credentials\EnrollableFactorProvider;
use Lock\Server\Shared\Credentials\EnrollmentOption;
use Lock\Server\Shared\Credentials\FactorEnrollment;
use Lock\Server\Shared\Credentials\FactorProvider;
use Lock\Server\Shared\Credentials\FactorRegistry as FactorRegistryContract;
use Lock\Server\Shared\Realms\RealmResolver;
use LogicException;

class FactorRegistry implements FactorRegistryContract
{
    public function __construct(private readonly RealmResolver $realms) {}

    /**
     * @var array<string, FactorProvider>
     */
    private array $providers = [];

    public function register(FactorProvider $provider): void
    {
        if (isset($this->providers[$provider->key()])) {
            throw new LogicException("A factor provider is already registered for [{$provider->key()}].");
        }

        $this->providers[$provider->key()] = $provider;
    }

    public function get(string $key): FactorProvider
    {
        return $this->providers[$key]
            ?? throw new LogicException("No factor provider is registered for [{$key}].");
    }

    public function enrollable(string $key): ?EnrollableFactorProvider
    {
        $provider = $this->providers[$key] ?? null;

        return $provider instanceof EnrollableFactorProvider ? $provider : null;
    }

    /**
     * @return array<string, FactorProvider>
     */
    public function providers(): array
    {
        return $this->providers;
    }

    /**
     * Backup providers stay out: recovery codes are backfilled, never picked.
     *
     * @return list<EnrollmentOption>
     */
    public function enrollmentOptions(): array
    {
        $options = [];

        foreach ($this->providers as $provider) {
            if ($provider->isBackup() || ! $provider instanceof EnrollableFactorProvider) {
                continue;
            }

            array_push($options, ...$provider->enrollmentOptions());
        }

        usort($options, static fn (EnrollmentOption $a, EnrollmentOption $b): int => [$a->sortOrder, $a->id] <=> [$b->sortOrder, $b->id]);

        return $options;
    }

    public function enrollmentOption(string $id): ?EnrollmentOption
    {
        foreach ($this->enrollmentOptions() as $option) {
            if ($option->id === $id) {
                return $option;
            }
        }

        return null;
    }

    /**
     * @return list<FactorEnrollment>
     */
    public function enrollments(Authenticatable $user): array
    {
        $enrollments = [];

        foreach ($this->providers as $provider) {
            array_push($enrollments, ...$provider->enrollments($user));
        }

        return $enrollments;
    }

    public function findEnrollment(Authenticatable $user, string $providerKey, string $id): ?FactorEnrollment
    {
        $provider = $this->providers[$providerKey] ?? null;

        if ($provider === null) {
            return null;
        }

        foreach ($provider->enrollments($user) as $enrollment) {
            if ($enrollment->id === $id) {
                return $enrollment;
            }
        }

        return null;
    }

    /**
     * Limited to oidc.credentials.challenge_providers.
     *
     * @return list<FactorEnrollment>
     */
    public function configuredChallengeableEnrollments(Authenticatable $user): array
    {
        return $this->challengeableEnrollments($user, $this->realms->current()->credentials()->challengeProviders);
    }

    public function hasChallengeableFactors(Authenticatable $user): bool
    {
        return $this->challengeableEnrollments($user) !== [];
    }

    /**
     * @param  list<string>|null  $providerKeys
     * @return list<FactorEnrollment>
     */
    public function challengeableEnrollments(Authenticatable $user, ?array $providerKeys = null): array
    {
        $enrollments = [];

        foreach ($this->providers as $provider) {
            if ($provider->isBackup() || ($providerKeys !== null && ! in_array($provider->key(), $providerKeys, true))) {
                continue;
            }

            foreach ($provider->enrollments($user) as $enrollment) {
                if ($enrollment->confirmedAt !== null) {
                    $enrollments[] = $enrollment;
                }
            }
        }

        return $enrollments;
    }
}
