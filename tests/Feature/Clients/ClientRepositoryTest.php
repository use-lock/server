<?php

declare(strict_types=1);

use Lock\Server\Clients\ClientRepository;

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
