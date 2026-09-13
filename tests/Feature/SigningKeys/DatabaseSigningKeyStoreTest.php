<?php

declare(strict_types=1);

/**
 * RFC 7517 §5 (JWK Set retained across rotation)
 */

use Illuminate\Support\Facades\DB;
use Lock\Server\Shared\Realms\IssuerResolver;
use Lock\Server\Shared\SigningKeys\Keyring;
use Lock\Server\SigningKeys\Models\SigningKey;
use Lock\Server\SigningKeys\SigningKeyGenerator;
use Lock\Server\SigningKeys\SigningKeyPair;
use Lock\Server\SigningKeys\SigningKeyStore;
use Lock\Server\Tokens\TokenInspector;

function useDatabaseSigningKeys(): SigningKeyStore
{
    return app(SigningKeyStore::class);
}

function databaseStoreRotate(): SigningKeyPair
{
    $store = useDatabaseSigningKeys();
    $generated = app(SigningKeyGenerator::class)->generate();
    $store->rotate($generated);

    return new SigningKeyPair($generated->publicKeyPem, $generated->privateKeyPem, $generated->kid);
}

it('fails loud when no key has been generated yet', function (): void {
    SigningKey::query()->delete();

    useDatabaseSigningKeys()->signingKey();
})->throws(RuntimeException::class, 'oidc:rotate-keys');

it('signs with the key stored by the last rotation', function (): void {
    $generated = databaseStoreRotate();

    $key = useDatabaseSigningKeys()->signingKey();

    expect($key->kid())->toBe($generated->kid())
        ->and($key->publicKeyPem)->toBe($generated->publicKeyPem)
        ->and($key->privateKey())->toBe($generated->privateKeyPem);
});

it('stores the private key encrypted at rest', function (): void {
    $generated = databaseStoreRotate();

    $raw = DB::table('oidc_signing_keys')->where('kid', $generated->kid())->value('private_key');

    expect($raw)->not->toContain('PRIVATE KEY')
        ->and(SigningKey::query()->where('kid', $generated->kid())->sole()->private_key)
        ->toBe($generated->privateKeyPem);
});

it('serves every retained kid from the jwks endpoint', function (): void {
    SigningKey::query()->delete();
    $first = databaseStoreRotate();
    $second = databaseStoreRotate();

    $response = $this->getJson('/.well-known/jwks.json')->assertOk();

    expect(array_column($response->json('keys'), 'kid'))->toBe([$second->kid(), $first->kid()]);
});

it('keeps tokens signed before a rotation verifiable', function (): void {
    databaseStoreRotate();
    $keyring = app(Keyring::class);
    $kidBefore = useDatabaseSigningKeys()->signingKey()->kid();

    $builder = $keyring->builder()
        ->issuedBy(app(IssuerResolver::class)->url())
        ->identifiedBy('token-id');
    $jwt = $keyring->sign($builder);

    databaseStoreRotate();

    expect(useDatabaseSigningKeys()->signingKey()->kid())->not->toBe($kidBefore)
        ->and(app(TokenInspector::class)->parse($jwt))->not->toBeNull();
});
