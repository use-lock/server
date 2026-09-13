<?php
declare(strict_types=1);

/**
 * RFC 8693 (token exchange) + RFC 9068 (issued access token) — session-token → browser-token issuance
 */

use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Validator;
use Lock\Server\Clients\ClientRepository;
use Lock\Server\Sessions\Actions\IssueScopedToken;
use Workbench\App\Models\User;

beforeEach(function (): void {
    config(['oidc.session.token.guard' => 'web']);
    $this->appClient = app(ClientRepository::class)->createAuthorizationCodeGrantClient('App', ['https://app.test/cb']);
    $this->appClient->forceFill(['allowed_exchange_audiences' => ['https://api.orders.test']])->save();
    config(['oidc.clients.first_party.client_id' => (string) $this->appClient->id, 'app.url' => 'https://op.test']);
    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    $this->startSession();
});

it('issues an audience-scoped token for the session user', function (): void {
    $this->actingAs($this->user);

    $issued = app(IssueScopedToken::class)('https://api.orders.test', ['openid']);

    expect($issued->audience)->toBe('https://api.orders.test')
        ->and($issued->scopes)->toBe(['openid'])
        ->and($issued->tokenType)->toBe('Bearer');

    $parsed = parseAccessToken($issued->accessToken);

    expect($parsed->headers()->get('typ'))->toBe('at+jwt')
        ->and($parsed->claims()->get('aud'))->toBe(['https://api.orders.test'])
        ->and($parsed->claims()->get('sub'))->toBe((string) $this->user->id)
        ->and((new Validator)->validate($parsed, new SignedWith(new Sha256, InMemory::plainText(signingPublicKey()))))->toBeTrue();
});

it('refuses to issue a token without an authenticated session', function (): void {
    app(IssueScopedToken::class)('https://api.orders.test', ['openid']);
})->throws(RuntimeException::class);
