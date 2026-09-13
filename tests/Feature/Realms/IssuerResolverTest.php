<?php

declare(strict_types=1);

/**
 * OpenID Connect Discovery 1.0 §3 (issuer)
 */

use Lock\Server\Realms\RealmIssuerResolver;
use Lock\Server\Shared\Realms\IssuerResolver;
use Lock\Server\Tokens\IdTokenBuilder;
use Lock\Server\Tokens\IdTokenRequest;
use Workbench\App\Models\User;

it('uses the configured issuer, trimming a trailing slash, or the app url as the origin', function (): void {
    config(['oidc.issuer' => 'https://id.example.com/']);

    expect(app(RealmIssuerResolver::class)->url())->toBe('https://id.example.com');

    config(['oidc.issuer' => null, 'app.url' => 'https://op.test/']);

    expect(app(RealmIssuerResolver::class)->url())->toBe('https://op.test');
});

it('drives discovery, protected resource metadata and the id_token issuer from the bound resolver', function (): void {
    config(['oidc.issuer' => 'https://ignored.example.com', 'oidc.resources' => ['mcp' => ['scopes' => []]]]);
    app()->instance(IssuerResolver::class, new class implements IssuerResolver
    {
        public function url(): string
        {
            return 'https://rebound.example.com';
        }
    });

    $this->getJson('/.well-known/openid-configuration')
        ->assertOk()
        ->assertJsonPath('issuer', 'https://rebound.example.com')
        ->assertJsonPath('jwks_uri', 'https://rebound.example.com/.well-known/jwks.json');

    $this->getJson('/.well-known/oauth-protected-resource/mcp')
        ->assertOk()
        ->assertJsonPath('resource', 'https://rebound.example.com/mcp')
        ->assertJsonPath('authorization_servers', ['https://rebound.example.com']);

    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    $idToken = parseIdToken(app(IdTokenBuilder::class)->build(new IdTokenRequest(
        userId: (string) $user->id,
        clientId: 'client-uuid',
        scopes: ['openid'],
        accessToken: 'access-token-jwt',
    )));

    expect($idToken->claims()->get('iss'))->toBe('https://rebound.example.com');
});
