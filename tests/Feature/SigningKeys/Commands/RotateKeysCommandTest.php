<?php

declare(strict_types=1);

use Lock\Server\SigningKeys\GeneratedSigningKeys;
use Lock\Server\SigningKeys\Models\SigningKey;
use Lock\Server\SigningKeys\SigningKeyPair;
use Lock\Server\SigningKeys\SigningKeyStore;

/** @return list<string> */
function signingKids(): array
{
    return array_map(fn (SigningKeyPair $key): string => $key->kid(), app(SigningKeyStore::class)->verificationKeys());
}

it('stores a new signing key and retires the current one for verification', function (): void {
    $currentKid = app(SigningKeyStore::class)->signingKey()->kid();

    $this->artisan('oidc:rotate-keys', ['--force' => true])
        ->expectsOutputToContain('stays in JWKS')
        ->assertSuccessful();

    expect(app(SigningKeyStore::class)->signingKey()->kid())->not->toBe($currentKid)
        ->and(signingKids())->toBe([app(SigningKeyStore::class)->signingKey()->kid(), $currentKid])
        ->and(SigningKey::query()->where('kid', $currentKid)->sole()->retired_at)->not->toBeNull();
});

it('aborts without storing when the confirmation is declined', function (): void {
    $currentKid = app(SigningKeyStore::class)->signingKey()->kid();

    $this->artisan('oidc:rotate-keys')
        ->expectsConfirmation('Generate a new signing keypair and store it?', 'no')
        ->assertSuccessful();

    expect(signingKids())->toBe([$currentKid]);
});

it('skips generation with --if-missing when a key already exists', function (): void {
    $currentKid = app(SigningKeyStore::class)->signingKey()->kid();

    $this->artisan('oidc:rotate-keys', ['--if-missing' => true])
        ->expectsOutputToContain('already exists')
        ->assertSuccessful();

    expect(signingKids())->toBe([$currentKid]);
});

it('generates the first key without confirmation with --if-missing when none exists', function (): void {
    SigningKey::query()->delete();

    $this->artisan('oidc:rotate-keys', ['--if-missing' => true])
        ->doesntExpectOutputToContain('stays in JWKS')
        ->assertSuccessful();

    expect(SigningKey::query()->count())->toBe(1)
        ->and(app(SigningKeyStore::class)->signingKey()->privateKey())->toContain('PRIVATE KEY');
});

it('fails with the store error when rotation cannot persist', function (): void {
    app()->instance(SigningKeyStore::class, new class implements SigningKeyStore
    {
        public function signingKey(): SigningKeyPair
        {
            return new SigningKeyPair('pub', 'p', 'kid');
        }

        public function verificationKeys(): array
        {
            return [$this->signingKey()];
        }

        public function rotate(GeneratedSigningKeys $keys): void
        {
            throw new RuntimeException('cannot persist');
        }
    });

    $this->artisan('oidc:rotate-keys', ['--force' => true])
        ->expectsOutputToContain('cannot persist')
        ->assertFailed();
});
