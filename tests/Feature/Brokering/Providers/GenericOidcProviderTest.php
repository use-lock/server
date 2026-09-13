<?php

declare(strict_types=1);

use Illuminate\Http\Client\Request as ClientRequest;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lock\Server\Brokering\PendingSocialRedirect;
use Lock\Server\Brokering\Providers\GenericOidcProvider;
use Lock\Server\Shared\Brokering\SocialAuthenticationException;
use Lock\Server\Shared\Brokering\SocialUser;
use Lock\Server\SigningKeys\Jwk;

function oidcTestProvider(): GenericOidcProvider
{
    return new GenericOidcProvider('corp', [
        'issuer' => 'https://idp.test',
        'client_id' => 'client-1',
        'client_secret' => 'shhh',
    ]);
}

/**
 * @param  array<string, mixed>  $overrides
 */
function fakeDiscovery(array $overrides = []): void
{
    Http::fake([
        'https://idp.test/.well-known/openid-configuration' => Http::response($overrides + [
            'issuer' => 'https://idp.test',
            'authorization_endpoint' => 'https://idp.test/authorize',
            'token_endpoint' => 'https://idp.test/token',
            'jwks_uri' => 'https://idp.test/jwks',
            'userinfo_endpoint' => 'https://idp.test/userinfo',
        ]),
        'https://idp.test/jwks' => Http::response([
            'keys' => [Jwk::fromPem(file_get_contents(__DIR__.'/../../../fixtures/oauth-public.key'))],
        ]),
    ]);
}

/**
 * Signs an upstream id_token with the test fixture keypair so JWKS
 * verification runs for real.
 *
 * @param  array<string, mixed>  $claims
 */
function upstreamIdToken(array $claims = [], ?string $nonce = null, string $issuer = 'https://idp.test', string $audience = 'client-1', ?string $kid = null, ?string $signWithPem = null, bool $expired = false): string
{
    $config = Configuration::forAsymmetricSigner(
        new Sha256,
        $signWithPem !== null
            ? InMemory::plainText($signWithPem)
            : InMemory::file(__DIR__.'/../../../fixtures/oauth-private.key'),
        InMemory::file(__DIR__.'/../../../fixtures/oauth-public.key'),
    );

    $now = new DateTimeImmutable;
    $builder = $config->builder()
        ->withHeader('kid', $kid ?? Jwk::fromPem(file_get_contents(__DIR__.'/../../../fixtures/oauth-public.key'))['kid'])
        ->issuedBy($issuer)
        ->permittedFor($audience)
        ->relatedTo((string) ($claims['sub'] ?? 'upstream-1'))
        ->issuedAt($expired ? $now->modify('-2 hours') : $now)
        ->expiresAt($expired ? $now->modify('-1 hour') : $now->modify('+1 hour'));

    if ($nonce !== null) {
        $builder = $builder->withClaim('nonce', $nonce);
    }

    foreach ($claims as $name => $value) {
        if ($name !== 'sub') {
            $builder = $builder->withClaim($name, $value);
        }
    }

    return $builder->getToken($config->signer(), $config->signingKey())->toString();
}

function oidcCallback(string $idToken): Request
{
    Http::fake([
        'https://idp.test/token' => Http::response([
            'access_token' => 'up-at',
            'refresh_token' => 'up-rt',
            'expires_in' => 3600,
            'id_token' => $idToken,
            'token_type' => 'Bearer',
        ]),
    ]);

    $request = Request::create('/auth/social/corp/callback', 'GET', ['code' => 'code-1', 'state' => 'state-1']);
    $request->setLaravelSession(app('session.store'));

    return $request;
}

it('reads endpoints from the discovery document for the redirect', function (): void {
    fakeDiscovery();

    $request = Request::create('/auth/social/corp');
    $request->setLaravelSession(app('session.store'));

    $response = oidcTestProvider()->redirect($request);
    parse_str((string) parse_url($response->headers->get('Location'), PHP_URL_QUERY), $params);

    expect($response->headers->get('Location'))->toStartWith('https://idp.test/authorize?')
        ->and($params['scope'])->toBe('openid profile email')
        ->and($params['nonce'])->not->toBeEmpty();
});

it('verifies the id_token against the upstream JWKS and returns the user', function (): void {
    fakeDiscovery();

    $idToken = upstreamIdToken([
        'email' => 'm@example.com',
        'email_verified' => true,
        'name' => 'M',
        'picture' => 'https://idp.test/avatar.png',
    ], nonce: 'nonce-1');

    $pending = new PendingSocialRedirect('corp', 'login', 'state-1', null, 'nonce-1');
    $user = oidcTestProvider()->user(oidcCallback($idToken), $pending);

    expect($user->id)->toBe('upstream-1')
        ->and($user->email)->toBe('m@example.com')
        ->and($user->emailVerified)->toBeTrue()
        ->and($user->name)->toBe('M')
        ->and($user->avatar)->toBe('https://idp.test/avatar.png')
        ->and($user->accessToken)->toBe('up-at')
        ->and($user->refreshToken)->toBe('up-rt')
        ->and($user->expiresIn)->toBe(3600);
});

it('rejects an id_token with a wrong nonce', function (): void {
    fakeDiscovery();
    $idToken = upstreamIdToken(nonce: 'other-nonce');

    $pending = new PendingSocialRedirect('corp', 'login', 'state-1', null, 'nonce-1');
    oidcTestProvider()->user(oidcCallback($idToken), $pending);
})->throws(SocialAuthenticationException::class);

it('rejects an id_token issued to a different audience', function (): void {
    fakeDiscovery();
    $idToken = upstreamIdToken(nonce: 'nonce-1', audience: 'someone-else');

    $pending = new PendingSocialRedirect('corp', 'login', 'state-1', null, 'nonce-1');
    oidcTestProvider()->user(oidcCallback($idToken), $pending);
})->throws(SocialAuthenticationException::class);

it('rejects an id_token from a different issuer', function (): void {
    fakeDiscovery();
    $idToken = upstreamIdToken(nonce: 'nonce-1', issuer: 'https://evil.test');

    $pending = new PendingSocialRedirect('corp', 'login', 'state-1', null, 'nonce-1');
    oidcTestProvider()->user(oidcCallback($idToken), $pending);
})->throws(SocialAuthenticationException::class);

it('rejects a malformed id_token', function (): void {
    fakeDiscovery();

    $pending = new PendingSocialRedirect('corp', 'login', 'state-1', null, 'nonce-1');
    oidcTestProvider()->user(oidcCallback('not-a-jwt'), $pending);
})->throws(SocialAuthenticationException::class);

it('rejects an id_token signed by a key not in the JWKS', function (): void {
    fakeDiscovery();

    $resource = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    openssl_pkey_export($resource, $otherPrivatePem);

    // Same kid as the JWKS key so key selection succeeds but the signature does not verify.
    $idToken = upstreamIdToken(nonce: 'nonce-1', signWithPem: $otherPrivatePem);

    $pending = new PendingSocialRedirect('corp', 'login', 'state-1', null, 'nonce-1');
    oidcTestProvider()->user(oidcCallback($idToken), $pending);
})->throws(SocialAuthenticationException::class);

it('rejects an expired id_token', function (): void {
    fakeDiscovery();
    $idToken = upstreamIdToken(nonce: 'nonce-1', expired: true);

    $pending = new PendingSocialRedirect('corp', 'login', 'state-1', null, 'nonce-1');
    oidcTestProvider()->user(oidcCallback($idToken), $pending);
})->throws(SocialAuthenticationException::class);

it('rejects an id_token whose kid matches no JWKS key', function (): void {
    fakeDiscovery();
    $idToken = upstreamIdToken(nonce: 'nonce-1', kid: 'unknown-kid');

    $pending = new PendingSocialRedirect('corp', 'login', 'state-1', null, 'nonce-1');
    oidcTestProvider()->user(oidcCallback($idToken), $pending);
})->throws(SocialAuthenticationException::class, 'No JWKS key matches the [corp] id_token.');

it('falls back to userinfo for profile claims missing from the id_token', function (): void {
    fakeDiscovery();
    Http::fake([
        'https://idp.test/userinfo' => Http::response([
            'sub' => 'upstream-1',
            'email' => 'm@example.com',
            'email_verified' => true,
            'name' => 'From Userinfo',
        ]),
    ]);

    $idToken = upstreamIdToken(nonce: 'nonce-1');

    $pending = new PendingSocialRedirect('corp', 'login', 'state-1', null, 'nonce-1');
    $user = oidcTestProvider()->user(oidcCallback($idToken), $pending);

    expect($user->name)->toBe('From Userinfo')
        ->and($user->email)->toBe('m@example.com');
});

it('isolates discovery and signing keys for providers with the same name and different issuers', function (): void {
    fakeDiscovery();
    $pending = new PendingSocialRedirect('corp', 'login', 'state-1', null, 'nonce-1');
    oidcTestProvider()->user(oidcCallback(upstreamIdToken([
        'email' => 'first@example.com',
        'name' => 'First',
    ], nonce: 'nonce-1')), $pending);

    $resource = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    openssl_pkey_export($resource, $privatePem);
    $publicPem = openssl_pkey_get_details($resource)['key'];
    $jwk = Jwk::fromPem($publicPem);
    $idToken = upstreamIdToken([
        'sub' => 'second-user',
        'email' => 'second@example.com',
        'name' => 'Second',
    ], nonce: 'nonce-1', issuer: 'https://second.test', kid: $jwk['kid'], signWithPem: $privatePem);
    Http::fake([
        'https://second.test/.well-known/openid-configuration' => Http::response([
            'issuer' => 'https://second.test',
            'authorization_endpoint' => 'https://second.test/authorize',
            'token_endpoint' => 'https://second.test/token',
            'jwks_uri' => 'https://second.test/jwks',
        ]),
        'https://second.test/jwks' => Http::response(['keys' => [$jwk]]),
        'https://second.test/token' => Http::response(['id_token' => $idToken, 'access_token' => 'second-token']),
    ]);
    $provider = new GenericOidcProvider('corp', [
        'issuer' => 'https://second.test',
        'client_id' => 'client-1',
        'client_secret' => 'second-secret',
    ]);
    $request = Request::create('/auth/social/corp/callback', 'GET', ['code' => 'second-code', 'state' => 'state-1']);
    $request->setLaravelSession(app('session.store'));

    $redirect = $provider->redirect($request);
    $user = $provider->user($request, $pending);

    expect($redirect->headers->get('Location'))->toStartWith('https://second.test/authorize?');
    expect($user->id)->toBe('second-user')
        ->and($user->email)->toBe('second@example.com');
    Http::assertSent(fn (ClientRequest $request): bool => $request->url() === 'https://second.test/token' && $request['client_secret'] === 'second-secret');
    Http::assertNotSent(fn (ClientRequest $request): bool => $request->url() === 'https://idp.test/token' && $request['client_secret'] === 'second-secret');
});

it('rejects userinfo without a matching string subject', function (mixed $subject): void {
    fakeDiscovery();
    $userinfo = ['email' => 'other@example.com', 'email_verified' => true, 'name' => 'Other'];

    if ($subject !== null) {
        $userinfo['sub'] = $subject;
    }

    Http::fake(['https://idp.test/userinfo' => Http::response($userinfo)]);
    $idToken = upstreamIdToken(['sub' => '123'], nonce: 'nonce-1');
    $pending = new PendingSocialRedirect('corp', 'login', 'state-1', null, 'nonce-1');

    expect(fn (): SocialUser => oidcTestProvider()->user(oidcCallback($idToken), $pending))
        ->toThrow(SocialAuthenticationException::class, 'The [corp] userinfo subject does not match the id_token.');
})->with([
    'missing subject' => [null],
    'different subject' => ['another-user'],
    'numeric subject' => [123],
]);
