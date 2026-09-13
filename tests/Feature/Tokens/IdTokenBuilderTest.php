<?php

declare(strict_types=1);

/**
 * OpenID Connect Core 1.0 §2 (id_token claims, acr/amr are the provider's), §3.1.3.6 (at_hash), RFC 8176 (amr)
 */

use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Validator;
use Lock\Server\Shared\Scopes\ClaimsRequest;
use Lock\Server\Shared\Scopes\ClaimsResolver;
use Lock\Server\SigningKeys\Jwk;
use Lock\Server\Tokens\IdTokenBuilder;
use Lock\Server\Tokens\IdTokenRequest;
use Workbench\App\Models\User;

beforeEach(function (): void {
    config(['app.url' => 'https://op.test']);
    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'email_verified_at' => now(), 'password' => 'x']);
});

/**
 * @param  list<string>  $amr
 */
function makeIdTokenRequest(User $user, ?string $nonce = null, ?int $authTime = null, array $amr = []): IdTokenRequest
{
    return new IdTokenRequest(
        userId: (string) $user->id,
        clientId: 'client-uuid',
        scopes: ['openid', 'email'],
        accessToken: 'access-token-jwt',
        nonce: $nonce,
        authTime: $authTime,
        amr: $amr,
    );
}

it('builds a signed id_token with the required claims', function (): void {
    $parsed = parseIdToken(app(IdTokenBuilder::class)->build(makeIdTokenRequest($this->user, nonce: 'n0nce', authTime: 1700000000)));
    $expectedAtHash = rtrim(strtr(base64_encode(substr(hash('sha256', 'access-token-jwt', true), 0, 16)), '+/', '-_'), '=');

    expect($parsed->headers()->get('alg'))->toBe('RS256')
        ->and($parsed->headers()->get('kid'))->toBe(Jwk::fromPem(signingPublicKey())['kid'])
        ->and($parsed->claims()->get('iss'))->toBe('https://op.test')
        ->and($parsed->claims()->get('sub'))->toBe((string) $this->user->id)
        ->and($parsed->claims()->get('aud'))->toBe(['client-uuid'])
        ->and($parsed->claims()->get('azp'))->toBe('client-uuid')
        ->and($parsed->claims()->get('nonce'))->toBe('n0nce')
        ->and($parsed->claims()->get('auth_time'))->toBe(1700000000)
        ->and($parsed->claims()->get('email'))->toBe('m@example.com')
        ->and($parsed->claims()->get('email_verified'))->toBeTrue()
        ->and($parsed->claims()->has('name'))->toBeFalse()
        ->and($parsed->claims()->get('at_hash'))->toBe($expectedAtHash)
        ->and((new Validator)->validate($parsed, new SignedWith(new Sha256, InMemory::plainText(signingPublicKey()))))->toBeTrue();
});

it('omits nonce, auth_time, amr and acr when they are not supplied', function (): void {
    $parsed = parseIdToken(app(IdTokenBuilder::class)->build(makeIdTokenRequest($this->user)));

    expect($parsed->claims()->has('nonce'))->toBeFalse()
        ->and($parsed->claims()->has('auth_time'))->toBeFalse()
        ->and($parsed->claims()->has('amr'))->toBeFalse()
        ->and($parsed->claims()->has('acr'))->toBeFalse();
});

it('drops protocol claims a claims resolver tries to emit', function (): void {
    app()->instance(ClaimsResolver::class, new class implements ClaimsResolver
    {
        public function resolve(ClaimsRequest $request): array
        {
            return ['sub' => 'someone-else', 'iss' => 'https://evil.test', 'aud' => ['other'], 'nonce' => 'forged', 'tenant' => 'acme'];
        }
    });

    $parsed = parseIdToken(app(IdTokenBuilder::class)->build(makeIdTokenRequest($this->user, nonce: 'n0nce')));

    expect($parsed->claims()->get('sub'))->toBe((string) $this->user->id)
        ->and($parsed->claims()->get('iss'))->toBe('https://op.test')
        ->and($parsed->claims()->get('aud'))->toBe(['client-uuid'])
        ->and($parsed->claims()->get('nonce'))->toBe('n0nce')
        ->and($parsed->claims()->get('tenant'))->toBe('acme');
});

it('emits amr and the acr the realm resolver derives from it', function (): void {
    $single = parseIdToken(app(IdTokenBuilder::class)->build(makeIdTokenRequest($this->user, amr: ['pwd'])));
    $multi = parseIdToken(app(IdTokenBuilder::class)->build(makeIdTokenRequest($this->user, amr: ['pwd', 'otp'])));

    expect($single->claims()->get('amr'))->toBe(['pwd'])
        ->and($single->claims()->get('acr'))->toBe('1')
        ->and($multi->claims()->get('amr'))->toBe(['pwd', 'otp'])
        ->and($multi->claims()->get('acr'))->toBe('2');
});
