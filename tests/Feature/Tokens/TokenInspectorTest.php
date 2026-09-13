<?php

declare(strict_types=1);

/**
 * RFC 9068 §4 (validating at+jwt: signature, key set, iss); RFC 8725 §3.1–3.2 (alg none, key confusion)
 */

use Lock\Server\Clients\ClientRepository;
use Lock\Server\Shared\Tokens\AccessTokenMinter;
use Lock\Server\SigningKeys\Models\SigningKey;
use Lock\Server\SigningKeys\SigningKeyGenerator;
use Lock\Server\SigningKeys\SigningKeyStore;
use Lock\Server\Tokens\TokenInspector;
use Workbench\App\Models\User;

function mintInspectorToken(): string
{
    $user = User::create(['name' => 'M', 'email' => 'm'.uniqid().'@example.com', 'password' => 'x']);
    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('App', ['https://rp.test/cb']);

    return app(AccessTokenMinter::class)
        ->mint((string) $user->id, $client->client_id, ['openid'], new DateInterval('PT1H'))
        ->toString();
}

function inspectorBase64Url(string $data): string
{
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

it('validates tokens signed by a retained previous key and rejects keys that are neither current nor retained', function (): void {
    $jwt = mintInspectorToken();
    $previousKid = app(SigningKeyStore::class)->signingKey()->kid();

    app(SigningKeyStore::class)->rotate(app(SigningKeyGenerator::class)->generate());

    expect(app(TokenInspector::class)->parse($jwt))->not->toBeNull();

    SigningKey::query()->where('kid', $previousKid)->delete();

    expect(app(TokenInspector::class)->parse($jwt))->toBeNull();
});

// RFC 9068 §4 — every path that accepts a token goes through parse(), so iss is checked once here
it('rejects a token issued under another issuer even when signed with the realm key', function (): void {
    config(['app.url' => 'https://op.test']);
    $jwt = mintInspectorToken();

    config(['app.url' => 'https://other-op.test']);

    expect(app(TokenInspector::class)->parse($jwt))->toBeNull();
});

it('rejects an unsigned token with header alg none', function (): void {
    $jwt = inspectorBase64Url((string) json_encode(['typ' => 'at+jwt', 'alg' => 'none']))
        .'.'.inspectorBase64Url((string) json_encode(['jti' => 'forged', 'sub' => '1', 'exp' => time() + 3600]))
        .'.';

    expect(app(TokenInspector::class)->parse($jwt))->toBeNull();
});

it('rejects an HS256 token signed with the server public key as the HMAC secret', function (): void {
    $header = inspectorBase64Url((string) json_encode(['typ' => 'at+jwt', 'alg' => 'HS256']));
    $payload = inspectorBase64Url((string) json_encode(['jti' => 'forged', 'sub' => '1', 'exp' => time() + 3600]));
    $signature = inspectorBase64Url(hash_hmac('sha256', $header.'.'.$payload, signingPublicKey(), true));

    expect(app(TokenInspector::class)->parse($header.'.'.$payload.'.'.$signature))->toBeNull();
});
