<?php

declare(strict_types=1);

use Lock\Server\Clients\ClientRepository;
use Lock\Server\Clients\Models\Client;
use Lock\Server\Shared\Scopes\ScopeRepository;
use Lock\Server\Tokens\DirectAccessTokenIssuer;
use Workbench\App\Models\User;

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

it('allows the wildcard scope for direct issuance when the client permits it', function (): void {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    $client = Client::factory()->create(['grant_types' => ['direct_access'], 'default_scopes' => [], 'optional_scopes' => ['*']]);

    expect(app(DirectAccessTokenIssuer::class)->issue($user, $client->snapshot(), 'wildcard', ['*'])->token->getAttribute('scopes'))->toBe(['*']);
});

it('adds the client default scopes for the grants no earlier artifact bounds', function (string $grantType): void {
    config(['oidc.scopes' => ['orders:read' => 'Read orders']]);
    $client = app(ClientRepository::class)->createClientCredentialsGrantClient('M2M');
    $client->forceFill(['default_scopes' => ['orders:read']])->save();

    expect(app(ScopeRepository::class)->grant(['openid'], $grantType, $client->snapshot()))->toBe(['openid', 'orders:read']);
})->with(['client_credentials', 'direct_access']);

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
    $client = Client::factory()->create(['grant_types' => ['direct_access']]);
    $client->forceFill(['optional_scopes' => ['openid']])->save();

    expect(app(ScopeRepository::class)->grant(['*', 'openid'], 'direct_access', $client->snapshot(), '1'))->toBe(['openid']);
});
