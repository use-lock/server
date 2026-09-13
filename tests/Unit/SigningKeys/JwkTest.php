<?php

declare(strict_types=1);

/**
 * RFC 7517 (JWK), RFC 7518 §6.3 (RSA parameters), RFC 7638 (JWK thumbprint as kid)
 */

use Lock\Server\SigningKeys\Jwk;

it('derives a JWK from a PEM public key', function (): void {
    $jwk = Jwk::fromPem(file_get_contents(__DIR__.'/../../fixtures/oauth-public.key'));

    expect($jwk)->toHaveKeys(['kty', 'use', 'alg', 'kid', 'n', 'e'])
        ->and($jwk['kty'])->toBe('RSA')
        ->and($jwk['use'])->toBe('sig')
        ->and($jwk['alg'])->toBe('RS256')
        ->and($jwk['n'])->not->toContain('+', '/', '=')
        ->and($jwk['e'])->toBe('AQAB');
});

it('computes an RFC 7638 thumbprint as the kid', function (): void {
    $jwk = Jwk::fromPem(file_get_contents(__DIR__.'/../../fixtures/oauth-public.key'));

    $expected = rtrim(strtr(base64_encode(hash(
        'sha256',
        json_encode(['e' => $jwk['e'], 'kty' => 'RSA', 'n' => $jwk['n']]),
        true,
    )), '+/', '-_'), '=');

    expect($jwk['kid'])->toBe($expected);
});

it('derives the same JWK from a PKCS#1 public key', function (): void {
    $pkcs8 = Jwk::fromPem(file_get_contents(__DIR__.'/../../fixtures/oauth-public.key'));
    $pkcs1 = Jwk::fromPem(file_get_contents(__DIR__.'/../../fixtures/oauth-public.pkcs1.key'));

    expect($pkcs1)->toBe($pkcs8);
});

it('rejects EC public keys', function (): void {
    Jwk::fromPem(file_get_contents(__DIR__.'/../../fixtures/ec-public.key'));
})->throws(RuntimeException::class, 'Only RSA public keys');
