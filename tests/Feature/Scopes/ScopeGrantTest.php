<?php

declare(strict_types=1);

use Lock\Server\Clients\ClientRepository;
use Lock\Server\Clients\Models\Client;
use Lock\Server\Shared\Scopes\ScopeRepository;

it('drops unknown scopes and keeps known ones', function (): void {
    config(['oidc.scopes' => ['project:update' => 'Update projects']]);
    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Test', ['https://rp.test/callback']);

    expect(app(ScopeRepository::class)->grant(['openid', 'project:update', 'nope'], 'authorization_code', $client->snapshot(), '1'))
        ->toBe(['openid', 'project:update']);
});

it('rejects the wildcard scope for authorization_code finalization', function (): void {
    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Test', ['https://rp.test/callback']);

    expect(app(ScopeRepository::class)->grant(['openid', '*'], 'authorization_code', $client->snapshot(), '1'))->toBe(['openid']);
});

it('adds the client default scopes for client credentials, which no earlier artifact bounds', function (): void {
    config(['oidc.scopes' => ['orders:read' => 'Read orders']]);
    $client = app(ClientRepository::class)->createClientCredentialsGrantClient('M2M');
    $client->forceFill(['default_scopes' => ['orders:read']])->save();

    expect(app(ScopeRepository::class)->grant(['openid'], 'client_credentials', $client->snapshot()))->toBe(['openid', 'orders:read']);
});

it('does not add default scopes for grants bounded by an earlier artifact', function (string $grantType): void {
    config(['oidc.scopes' => ['orders:read' => 'Read orders']]);
    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Test', ['https://rp.test/callback']);
    $client->forceFill(['default_scopes' => ['orders:read']])->save();

    expect(app(ScopeRepository::class)->grant(['openid'], $grantType, $client->snapshot(), '1'))->toBe(['openid']);
})->with(['authorization_code', 'refresh_token', 'urn:ietf:params:oauth:grant-type:token-exchange']);

it('drops a known scope the client is not assigned', function (): void {
    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Test', ['https://rp.test/callback']);
    $client->forceFill(['optional_scopes' => ['openid']])->save();

    expect(app(ScopeRepository::class)->grant(['openid', 'email'], 'authorization_code', $client->snapshot(), '1'))->toBe(['openid']);
});

it('keeps the wildcard only while the client may request every scope', function (): void {
    $client = Client::factory()->create(['grant_types' => ['client_credentials']]);
    $client->forceFill(['optional_scopes' => ['openid']])->save();

    expect(app(ScopeRepository::class)->grant(['*', 'openid'], 'client_credentials', $client->snapshot()))->toBe(['openid']);
});
