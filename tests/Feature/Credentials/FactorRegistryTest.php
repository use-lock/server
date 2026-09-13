<?php

declare(strict_types=1);

use Illuminate\Contracts\Auth\Authenticatable;
use Lock\Server\Credentials\FactorRegistry;
use Lock\Server\Credentials\TotpFactorProvider;
use Lock\Server\Shared\Credentials\FactorChallenge;
use Lock\Server\Shared\Credentials\FactorEnrollment;
use Lock\Server\Shared\Credentials\FactorProvider;
use Lock\Server\Shared\Credentials\FactorVerification;
use Lock\Server\Shared\Realms\RealmResolver;
use Workbench\App\Models\User;

it('registers factor providers by stable key and aggregates enrollments', function (): void {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);
    $provider = new class implements FactorProvider
    {
        public function key(): string
        {
            return 'custom';
        }

        public function isBackup(): bool
        {
            return false;
        }

        public function enrollments(Authenticatable $user): array
        {
            return [new FactorEnrollment('custom', 'enrollment-1', 'Custom key', now(), null)];
        }

        public function beginChallenge(Authenticatable $user, FactorEnrollment $enrollment): FactorChallenge
        {
            return new FactorChallenge($enrollment, ['prompt' => 'Touch key']);
        }

        public function verify(Authenticatable $user, FactorChallenge $challenge, array $input): FactorVerification
        {
            return new FactorVerification(true, ['custom']);
        }
    };

    $registry = new FactorRegistry(app(RealmResolver::class));
    $registry->register($provider);

    expect($registry->get('custom'))->toBe($provider)
        ->and($registry->enrollments($user))->toHaveCount(1)
        ->and($registry->challengeableEnrollments($user))->toHaveCount(1);
});

it('limits configured challengeable enrollments to the challenge providers config', function (): void {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);
    $registry = app(FactorRegistry::class);
    $factor = app(TotpFactorProvider::class)->enroll($user);
    $factor->forceFill(['confirmed_at' => now()])->save();
    $user->passkeys()->create(['name' => 'Key', 'credential_id' => 'credential-id', 'credential' => []]);

    config(['oidc.credentials.challenge_providers' => ['totp', 'webauthn']]);
    expect(array_column($registry->configuredChallengeableEnrollments($user), 'providerKey'))
        ->toBe(['totp', 'webauthn']);

    config(['oidc.credentials.challenge_providers' => ['totp']]);
    expect(array_column($registry->configuredChallengeableEnrollments($user), 'providerKey'))
        ->toBe(['totp']);
});

it('reports challengeable factors only once a confirmed factor exists', function (): void {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);
    $registry = app(FactorRegistry::class);

    expect($registry->hasChallengeableFactors($user))->toBeFalse();

    $factor = app(TotpFactorProvider::class)->enroll($user);
    $factor->forceFill(['confirmed_at' => now()])->save();

    expect($registry->hasChallengeableFactors($user))->toBeTrue();
});

it('collects enrollment options across providers in display order, leaving backup providers out', function (): void {
    $registry = app(FactorRegistry::class);
    $options = $registry->enrollmentOptions();

    expect(array_column($options, 'id'))->toBe(['passkey', 'security_key', 'totp'])
        ->and(array_column($options, 'sortOrder'))->toBe([10, 20, 30])
        ->and(array_column($options, 'providerKey'))->not->toContain('recovery_code')
        ->and($registry->enrollmentOption('security_key')?->providerKey)->toBe('webauthn')
        ->and($registry->enrollmentOption('nope'))->toBeNull();
});

it('finds a confirmed enrollment by provider and id', function (): void {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);
    $factor = app(TotpFactorProvider::class)->enroll($user);
    $factor->forceFill(['confirmed_at' => now()])->save();

    $found = app(FactorRegistry::class)->findEnrollment($user, 'totp', (string) $factor->getKey());

    expect($found)->toBeInstanceOf(FactorEnrollment::class)
        ->and($found->providerKey)->toBe('totp');
});

it('returns null for an unknown provider, an unknown id, or another user', function (): void {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);
    $other = User::create(['name' => 'O', 'email' => 'o@example.com', 'password' => 'secret']);
    $factor = app(TotpFactorProvider::class)->enroll($user);
    $registry = app(FactorRegistry::class);

    expect($registry->findEnrollment($user, 'nope', (string) $factor->getKey()))->toBeNull()
        ->and($registry->findEnrollment($user, 'totp', 'not-an-id'))->toBeNull()
        ->and($registry->findEnrollment($other, 'totp', (string) $factor->getKey()))->toBeNull();
});

it('rejects duplicate factor provider keys', function (): void {
    $registry = app(FactorRegistry::class);
    $provider = $registry->get('totp');

    expect(fn () => $registry->register($provider))->toThrow(LogicException::class);
});
