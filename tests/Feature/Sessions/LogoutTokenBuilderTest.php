<?php

declare(strict_types=1);

/**
 * OpenID Connect Back-Channel Logout 1.0 §2.4 (logout token claims, events object, no nonce)
 */

use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Validator;
use Lock\Server\Sessions\LogoutTokenBuilder;
use Lock\Server\Sessions\Models\OidcSession;
use Lock\Server\Sessions\OidcSessionRepository;
use Workbench\App\Models\User;

it('mints a signed logout token with the spec claims and an events object', function (): void {
    $user = User::factory()->create();
    $sid = app(OidcSessionRepository::class)->start((string) $user->getKey());
    $session = OidcSession::query()->findOrFail($sid);

    $jwt = app(LogoutTokenBuilder::class)->build($session, 'client-xyz');
    $token = parseAccessToken($jwt);
    [, $payload] = explode('.', $jwt);

    expect($token->headers()->get('typ'))->toBe('logout+jwt')
        ->and($token->claims()->get('aud'))->toBe(['client-xyz'])
        ->and($token->claims()->get('sub'))->toBe((string) $user->getKey())
        ->and($token->claims()->get('sid'))->toBe($sid)
        ->and($token->claims()->has('nonce'))->toBeFalse()
        ->and((new Validator)->validate($token, new SignedWith(new Sha256, InMemory::plainText(signingPublicKey()))))->toBeTrue()
        ->and(base64_decode(strtr($payload, '-_', '+/')))
        ->toContain('"events":{"http://schemas.openid.net/event/backchannel-logout":{}}');
});
