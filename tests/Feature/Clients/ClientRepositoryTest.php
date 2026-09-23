<?php

declare(strict_types=1);

use Lock\Server\Clients\ClientRepository;
use Lock\Server\Shared\Clients\TokenEndpointAuthMethod;
use Workbench\App\Models\User;

it('assigns the realm default and optional scopes to a new client', function (): void {
    config(['oidc.clients.default_scopes' => ['openid'], 'oidc.clients.optional_scopes' => ['email']]);

    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/callback']);

    expect($client->default_scopes)->toBe(['openid'])
        ->and($client->optional_scopes)->toBe(['email'])
        ->and($client->snapshot()->assignedScopes())->toBe(['openid', 'email'])
        ->and($client->snapshot()->allowsScope('email'))->toBeTrue()
        ->and($client->snapshot()->allowsScope('profile'))->toBeFalse();
});

it('lets a new client request every catalog scope by default', function (): void {
    $client = app(ClientRepository::class)->createClientCredentialsGrantClient('M2M');

    expect($client->default_scopes)->toBe([])
        ->and($client->optional_scopes)->toBe(['*'])
        ->and($client->snapshot()->allowsScope('anything'))->toBeTrue();
});

it('honours a resource-qualified scope assignment only for that resource', function (): void {
    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/callback']);
    $client->forceFill([
        'default_scopes' => ['openid', 'https://api.internal/orders orders:read'],
        'optional_scopes' => ['https://api.internal/billing *'],
    ])->save();

    expect($client->snapshot()->defaultScopes())->toBe(['openid'])
        ->and($client->snapshot()->defaultScopes(['https://api.internal/orders']))->toBe(['openid', 'orders:read'])
        ->and($client->snapshot()->assignedScopes(['https://api.internal/billing']))->toBe(['openid', '*'])
        ->and($client->snapshot()->allowsScope('orders:read'))->toBeFalse()
        ->and($client->snapshot()->allowsScope('orders:read', ['https://api.internal/orders']))->toBeTrue()
        ->and($client->snapshot()->allowsScope('anything', ['https://api.internal/billing']))->toBeTrue()
        ->and($client->snapshot()->allowsScope('anything', ['https://api.internal/orders']))->toBeFalse();
});

it('provisions a machine client whose fixed credentials, scopes and audiences the token endpoint honours', function (): void {
    $orders = 'https://api.internal/orders';
    config(['oidc.resources' => [$orders => ['scopes' => ['orders:read', 'orders:write']]]]);

    app(ClientRepository::class)->create(
        name: 'ERP sync',
        grantTypes: ['client_credentials'],
        clientId: 'erp-sync',
        secret: 'provisioned-secret',
        defaultScopes: ['orders:read'],
        optionalScopes: [],
        allowedAudiences: [$orders],
    );

    $credentials = ['grant_type' => 'client_credentials', 'client_id' => 'erp-sync', 'client_secret' => 'provisioned-secret', 'resource' => $orders];

    $this->post('/oauth/token', $credentials)->assertOk()->assertJsonPath('scope', 'orders:read');
    $this->post('/oauth/token', [...$credentials, 'scope' => 'orders:write'])->assertStatus(400)->assertJsonPath('error', 'invalid_scope');
    $this->post('/oauth/token', [...$credentials, 'resource' => 'https://api.internal/billing'])->assertStatus(400)->assertJsonPath('error', 'invalid_target');
});

it('records the owner of a client as a polymorphic relation', function (): void {
    $user = User::create(['name' => 'Owner', 'email' => 'owner@example.com', 'password' => 'x']);

    $client = app(ClientRepository::class)->create('Owned', ['client_credentials'], owner: $user);

    expect($client->fresh()?->owner?->is($user))->toBeTrue();
});

it('refuses a secret for a public client', function (): void {
    app(ClientRepository::class)->create(
        name: 'SPA',
        grantTypes: ['authorization_code'],
        redirectUris: ['https://spa.test/callback'],
        authMethod: TokenEndpointAuthMethod::None,
        secret: 'not-allowed',
    );
})->throws(InvalidArgumentException::class, 'A public client cannot have a secret.');
