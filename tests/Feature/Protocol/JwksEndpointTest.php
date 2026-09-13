<?php
declare(strict_types=1);

/**
 * RFC 7517 §5 (JWK Set) + RFC 7518 §6.3 (RSA params); RFC 7638 (JWK thumbprint / kid)
 */

use Lock\Server\SigningKeys\Jwk;

it('serves the public key as a JWKS document', function (): void {
    $expected = Jwk::fromPem(file_get_contents(__DIR__.'/../../fixtures/oauth-public.key'));

    $this->getJson('/.well-known/jwks.json')
        ->assertOk()
        ->assertHeader('Cache-Control', 'max-age=3600, public')
        ->assertJson(['keys' => [$expected]]);
});

it('serves the retired key alongside the active key after a rotation', function (): void {
    $retiredKid = $this->getJson('/.well-known/jwks.json')->json('keys.0.kid');

    $this->artisan('oidc:rotate-keys', ['--force' => true])->assertSuccessful();

    $kids = collect((array) $this->getJson('/.well-known/jwks.json')->json('keys'))->pluck('kid')->all();

    expect($kids)->toHaveCount(2)->toContain($retiredKid)
        ->and($kids[0])->not->toBe($retiredKid);
});
