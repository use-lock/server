<?php

declare(strict_types=1);

use Illuminate\Http\Client\Request as ClientRequest;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Ecdsa\Sha256 as Es256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Validator;
use Lock\Server\Brokering\PendingSocialRedirect;
use Lock\Server\Brokering\Providers\AppleProvider;

/**
 * @return array{0: string, 1: string} [privatePem, publicPem]
 */
function appleEcKeypair(): array
{
    $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
    openssl_pkey_export($key, $privatePem);

    return [$privatePem, openssl_pkey_get_details($key)['key']];
}

function appleProvider(string $privatePem): AppleProvider
{
    return new AppleProvider('apple', [
        'client_id' => 'com.example.app',
        'team_id' => 'TEAM123',
        'key_id' => 'KEY456',
        'private_key' => $privatePem,
    ]);
}

it('requests form_post and name/email scopes without PKCE', function (): void {
    [$privatePem] = appleEcKeypair();

    $request = Request::create('/auth/social/apple');
    $request->setLaravelSession(app('session.store'));

    $response = appleProvider($privatePem)->redirect($request);
    parse_str((string) parse_url($response->headers->get('Location'), PHP_URL_QUERY), $params);

    expect($response->headers->get('Location'))->toStartWith('https://appleid.apple.com/auth/authorize?')
        ->and($params['response_mode'])->toBe('form_post')
        ->and($params['scope'])->toBe('name email')
        ->and($params)->not->toHaveKey('code_challenge');
})->skip(fn (): bool => ! function_exists('openssl_pkey_new'), 'requires openssl');

it('signs the client secret as an ES256 JWT with Apple claims', function (): void {
    [$privatePem, $publicPem] = appleEcKeypair();

    Http::fake(function ($httpRequest) {
        expect($httpRequest->url())->toBe('https://appleid.apple.com/auth/token');

        return Http::response(['error' => 'stop_here'], 400);
    });

    $pending = new PendingSocialRedirect('apple', 'login', 'state-1', null, 'nonce-1');
    $request = Request::create('/auth/social/apple/callback', 'GET', ['code' => 'code-1', 'state' => 'state-1']);
    $request->setLaravelSession(app('session.store'));

    try {
        appleProvider($privatePem)->user($request, $pending);
    } catch (Throwable) {
        // The 400 aborts the flow; we only care about the request that was sent.
    }

    Http::assertSent(function (ClientRequest $httpRequest) use ($publicPem): bool {
        /** @var UnencryptedToken $secret */
        $secret = new Parser(new JoseEncoder)->parse($httpRequest['client_secret']);

        return (new Validator)->validate($secret, new SignedWith(new Es256, InMemory::plainText($publicPem)))
            && $secret->headers()->get('kid') === 'KEY456'
            && $secret->claims()->get('iss') === 'TEAM123'
            && $secret->claims()->get('sub') === 'com.example.app'
            && $secret->claims()->get('aud') === ['https://appleid.apple.com'];
    });
})->skip(fn (): bool => ! function_exists('openssl_pkey_new'), 'requires openssl');

it('uses the first-consent user payload for the name', function (): void {
    [$privatePem] = appleEcKeypair();
    $provider = new class('apple', ['client_id' => 'com.example.app', 'team_id' => 'TEAM123', 'key_id' => 'KEY456', 'private_key' => $privatePem]) extends AppleProvider
    {
        protected function verifiedIdTokenClaims(string $idToken, ?string $nonce): array
        {
            return ['sub' => 'apple-1', 'email' => 'm@privaterelay.appleid.com', 'email_verified' => 'true'];
        }
    };

    Http::fake([
        'https://appleid.apple.com/.well-known/openid-configuration' => Http::response([
            'issuer' => 'https://appleid.apple.com',
            'authorization_endpoint' => 'https://appleid.apple.com/auth/authorize',
            'token_endpoint' => 'https://appleid.apple.com/auth/token',
            'jwks_uri' => 'https://appleid.apple.com/auth/keys',
        ]),
        'https://appleid.apple.com/auth/token' => Http::response(['access_token' => 'ap-at', 'id_token' => 'stubbed', 'token_type' => 'Bearer']),
    ]);

    $pending = new PendingSocialRedirect('apple', 'login', 'state-1', null, 'nonce-1');
    $request = Request::create('/auth/social/apple/callback', 'GET', [
        'code' => 'code-1',
        'state' => 'state-1',
        'user' => json_encode(['name' => ['firstName' => 'Mona', 'lastName' => 'Lisa']]),
    ]);
    $request->setLaravelSession(app('session.store'));

    $user = $provider->user($request, $pending);

    expect($user->name)->toBe('Mona Lisa')
        ->and($user->email)->toBe('m@privaterelay.appleid.com')
        ->and($user->emailVerified)->toBeTrue();
})->skip(fn (): bool => ! function_exists('openssl_pkey_new'), 'requires openssl');
