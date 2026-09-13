<?php

declare(strict_types=1);

/**
 * RFC 9068 §2.1 (at+jwt header), §2.2 (claims: aud names resources, client_id names the client); RFC 8693 §4.1 (act)
 */

use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Validator;
use Lock\Server\Clients\ClientRepository;
use Lock\Server\Clients\Models\Client;
use Lock\Server\Shared\Tokens\AccessTokenMinter;
use Lock\Server\Shared\Tokens\MintedAccessToken;
use Lock\Server\SigningKeys\Jwk;
use Lock\Server\Tokens\Models\AccessToken;
use Lock\Server\Tokens\TokenInspector;
use Workbench\App\Models\User;

beforeEach(function (): void {
    config(['app.url' => 'https://op.test']);
    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    $this->client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('App', ['https://rp.test/cb']);
});

/**
 * @param  string[]  $scopes
 * @param  string[]  $audiences
 * @param  array<string, mixed>  $extraClaims
 * @param  array<string, mixed>|null  $actor
 */
function mintAccessToken(Client $client, User $user, array $scopes = ['openid', 'email'], array $audiences = [], array $extraClaims = [], ?array $actor = null): MintedAccessToken
{
    return app(AccessTokenMinter::class)->mint((string) $user->id, $client->client_id, $scopes, new DateInterval('PT1H'), $audiences, $extraClaims, $actor);
}

it('emits a signed RFC 9068 at+jwt access token with a persisted record', function (): void {
    $minted = mintAccessToken($this->client, $this->user);
    $parsed = parseAccessToken($minted->jwt);
    $record = app(TokenInspector::class)->accessToken($minted->jwt);

    expect($parsed->headers()->get('typ'))->toBe('at+jwt')
        ->and($parsed->headers()->get('kid'))->toBe(Jwk::fromPem(signingPublicKey())['kid'])
        ->and($parsed->claims()->get('iss'))->toBe('https://op.test')
        ->and($parsed->claims()->get('sub'))->toBe((string) $this->user->id)
        ->and($parsed->claims()->get('client_id'))->toBe($this->client->client_id)
        ->and($parsed->claims()->get('aud'))->toBe(['https://op.test'])
        ->and($parsed->claims()->get('scope'))->toBe('openid email')
        ->and($parsed->claims()->get('scopes'))->toBe(['openid', 'email'])
        ->and($parsed->claims()->get('jti'))->toBe($minted->jti)
        ->and($parsed->claims()->has('iat'))->toBeTrue()
        ->and($parsed->claims()->has('nbf'))->toBeTrue()
        ->and($parsed->claims()->has('exp'))->toBeTrue()
        ->and((new Validator)->validate($parsed, new SignedWith(new Sha256, InMemory::plainText(signingPublicKey()))))->toBeTrue()
        ->and((string) $record?->getAttribute('user_id'))->toBe((string) $this->user->id)
        ->and((string) $record?->getAttribute('client_id'))->toBe((string) $this->client->getKey())
        ->and($record?->getAttribute('scopes'))->toBe(['openid', 'email'])
        ->and($record?->isRevoked())->toBeFalse();
});

// RFC 9068 §3 — aud is the requested resource, or the realm issuer as the default resource indicator
it('addresses the token to the realm issuer unless an audience is given', function (): void {
    config(['app.url' => 'https://op.test', 'oidc.issuer' => null, 'oidc.resources' => ['https://api.example/orders' => []]]);

    $defaulted = mintAccessToken($this->client, $this->user);
    $explicit = mintAccessToken($this->client, $this->user, audiences: ['https://api.internal/orders']);

    expect(parseAccessToken($defaulted->jwt)->claims()->get('aud'))->toBe(['https://op.test'])
        ->and($defaulted->audience)->toBe(['https://op.test'])
        ->and(AccessToken::query()->find($defaulted->jti)?->audience)->toBe(['https://op.test'])
        ->and(AccessToken::query()->find($explicit->jti)?->audience)->toBe(['https://api.internal/orders'])
        ->and(parseAccessToken($defaulted->jwt)->claims()->get('client_id'))->toBe($this->client->client_id)
        ->and(parseAccessToken($explicit->jwt)->claims()->get('aud'))->toBe(['https://api.internal/orders'])
        ->and($explicit->audience)->toBe(['https://api.internal/orders']);
});

it('falls back to the client id as subject for a userless token', function (): void {
    $minted = app(AccessTokenMinter::class)->mint(null, $this->client->client_id, [], new DateInterval('PT1H'));

    expect(parseAccessToken($minted->jwt)->claims()->get('sub'))->toBe($this->client->client_id)
        ->and($minted->userId)->toBeNull();
});

it('does not let extra claims override protected access-token claims', function (): void {
    $minted = mintAccessToken($this->client, $this->user, extraClaims: [
        'scope' => 'forged',
        'scopes' => ['forged'],
        'client_id' => 'forged-client',
        'cnf' => ['jkt' => 'forged'],
        'act' => ['client_id' => 'forged-client'],
        'sid' => 'forged',
        'tier' => 'gold',
    ]);

    $parsed = parseAccessToken($minted->jwt);

    expect($parsed->claims()->get('scope'))->toBe('openid email')
        ->and($parsed->claims()->get('scopes'))->toBe(['openid', 'email'])
        ->and($parsed->claims()->get('client_id'))->toBe($this->client->client_id)
        ->and($parsed->claims()->has('cnf'))->toBeFalse()
        ->and($parsed->claims()->has('act'))->toBeFalse()
        ->and($parsed->claims()->has('sid'))->toBeFalse()
        ->and($parsed->claims()->get('tier'))->toBe('gold');
});

it('emits the given actor as the act claim', function (): void {
    $minted = mintAccessToken($this->client, $this->user, actor: ['client_id' => 'trusted']);

    expect(parseAccessToken($minted->jwt)->claims()->get('act'))->toBe(['client_id' => 'trusted']);
});

it('refuses to mint for a revoked client', function (): void {
    $this->client->forceFill(['revoked_at' => now()])->save();

    expect(fn (): MintedAccessToken => mintAccessToken($this->client, $this->user))->toThrow(RuntimeException::class);
});
