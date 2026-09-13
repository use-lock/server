<?php

declare(strict_types=1);

use Lock\Server\Clients\ClientRepository;
use Lock\Server\Clients\Models\Client;
use Lock\Server\Shared\Clients\ClientProvisioner;
use Lock\Server\Shared\Clients\FirstPartyClientProvisioningException;
use Lock\Server\Tests\FeatureTestCase;
use Lock\Server\Tokens\Models\AccessToken;
use Workbench\App\Models\User;

it('creates a confidential managed client and returns its plain secret once', function (): void {
    $result = app(ClientProvisioner::class)->provision(
        name: 'First-party app',
        redirectUris: ['https://app.test/login/callback'],
        postLogoutRedirectUris: ['https://app.test'],
        allowedExchangeAudiences: ['https://api.test/orders'],
    );

    expect($result->wasCreated)->toBeTrue()
        ->and($result->clientSecret)->toBeString()->not->toBeEmpty()
        ->and(Client::query()->findOrFail($result->client->key)->secret)->toBe($result->clientSecret)
        ->and(Client::query()->findOrFail($result->client->key)->getRawOriginal('provisioning_key'))->toBe('first-party')
        ->and($result->client->redirectUris)->toBe(['https://app.test/login/callback'])
        ->and($result->client->postLogoutRedirectUris)->toBe(['https://app.test'])
        ->and($result->client->allowedAudiences)->toBe(['https://api.test/orders'])
        ->and($result->client->grantTypes)->toBe(['authorization_code', 'refresh_token', FeatureTestCase::TOKEN_EXCHANGE_GRANT])
        ->and($result->secretRotated)->toBeFalse();
});

it('gives every realm its own first-party client', function (): void {
    $provisioner = app(ClientProvisioner::class);

    config(['oidc.realm' => 'admin']);
    $admin = $provisioner->provision('Admin console', ['https://admin.test/callback']);

    config(['oidc.realm' => 'partners']);
    $partners = $provisioner->provision('Partner portal', ['https://partners.test/callback']);

    expect($partners->wasCreated)->toBeTrue()
        ->and($partners->client->key === $admin->client->key)->toBeFalse()
        ->and($partners->client->realm)->toBe('partners')
        ->and(Client::query()->findOrFail($admin->client->key)->name)->toBe('Admin console');
});

it('reconciles the managed client within its own realm only', function (): void {
    $provisioner = app(ClientProvisioner::class);

    config(['oidc.realm' => 'admin']);
    $provisioner->provision('Admin console', ['https://admin.test/callback']);

    config(['oidc.realm' => 'partners']);
    $provisioner->provision('Partner portal', ['https://partners.test/callback']);
    $reconciled = $provisioner->provision('Partner portal renamed', ['https://partners.test/callback']);

    expect($reconciled->wasCreated)->toBeFalse()
        ->and(Client::query()->where('provisioning_key', 'first-party')->count())->toBe(2);
});

it('reconciles the managed client without rotating its secret', function (): void {
    $provisioner = app(ClientProvisioner::class);
    $created = $provisioner->provision('Old name', ['https://old.test/callback']);
    $storedSecret = Client::query()->findOrFail($created->client->key)->getRawOriginal('secret');

    $result = $provisioner->provision(
        'New name',
        ['https://new.test/callback', 'https://new.test/callback'],
        ['https://new.test'],
    );

    expect($result->wasCreated)->toBeFalse()
        ->and($result->client->clientId)->toBe($created->client->clientId)
        ->and($result->clientSecret)->toBeNull()
        ->and($result->client->name)->toBe('New name')
        ->and($result->client->redirectUris)->toBe(['https://new.test/callback'])
        ->and(Client::query()->findOrFail($result->client->key)->getRawOriginal('secret'))->toBe($storedSecret)
        ->and($result->client->grantTypes)->toBe(['authorization_code', 'refresh_token'])
        ->and($result->secretRotated)->toBeFalse();
});

it('reconciles the managed client with a matching credential and returns the verified secret', function (): void {
    $provisioner = app(ClientProvisioner::class);
    $created = $provisioner->provision('Old name', ['https://old.test/callback']);
    $storedSecret = Client::query()->findOrFail($created->client->key)->getRawOriginal('secret');

    $result = $provisioner->provision(
        name: 'New name',
        redirectUris: ['https://new.test/callback'],
        postLogoutRedirectUris: ['https://new.test'],
        allowedExchangeAudiences: ['https://api.test/orders'],
        existingClientSecret: $created->clientSecret,
    );

    expect($created->clientSecret)->toBeString()->not->toBeEmpty()
        ->and($result->wasCreated)->toBeFalse()
        ->and($result->client->clientId)->toBe($created->client->clientId)
        ->and($result->clientSecret)->toBe($created->clientSecret)
        ->and($result->client->name)->toBe('New name')
        ->and($result->client->redirectUris)->toBe(['https://new.test/callback'])
        ->and(Client::query()->findOrFail($result->client->key)->getRawOriginal('secret'))->toBe($storedSecret)
        ->and($result->client->grantTypes)->toBe(['authorization_code', 'refresh_token', FeatureTestCase::TOKEN_EXCHANGE_GRANT]);
});

it('rejects a mismatched managed client credential without mutating the client', function (string $existingClientSecret): void {
    $provisioner = app(ClientProvisioner::class);
    $created = $provisioner->provision('Original name', ['https://original.test/callback']);
    $originalAttributes = Client::query()->findOrFail($created->client->key)->getRawOriginal();

    expect(fn () => $provisioner->provision(
        name: 'Changed name',
        redirectUris: ['https://changed.test/callback'],
        postLogoutRedirectUris: ['https://changed.test'],
        allowedExchangeAudiences: ['https://api.test/changed'],
        existingClientSecret: $existingClientSecret,
    ))->toThrow(
        FirstPartyClientProvisioningException::class,
        'The existing first-party client secret does not match.',
    );

    expect(Client::query()->findOrFail($created->client->key)->getRawOriginal())->toBe($originalAttributes);
})->with([
    'wrong secret' => 'wrong-secret',
    'empty secret' => '',
]);

it('adopts an explicit eligible client and then rotates only when requested', function (): void {
    $existing = app(ClientRepository::class)
        ->createAuthorizationCodeGrantClient('Existing', ['https://existing.test/callback']);
    $oldSecret = $existing->secret;

    $adopted = app(ClientProvisioner::class)->provision(
        'Adopted',
        ['https://app.test/login/callback'],
        adoptClientId: (string) $existing->getKey(),
    );

    $rotated = app(ClientProvisioner::class)->provision(
        'Adopted',
        ['https://app.test/login/callback'],
        rotateSecret: true,
    );

    expect($adopted->client->clientId)->toBe((string) $existing->getKey())
        ->and($adopted->clientSecret)->toBeNull()
        ->and($rotated->secretRotated)->toBeTrue()
        ->and($rotated->clientSecret)->toBeString()->not->toBeEmpty()
        ->and(Client::query()->findOrFail($rotated->client->key)->secret)->not->toBe($oldSecret);
});

it('rejects a mismatched adoption credential without mutating the client', function (): void {
    $existing = app(ClientRepository::class)
        ->createAuthorizationCodeGrantClient('Existing', ['https://existing.test/callback']);
    $originalAttributes = $existing->refresh()->getRawOriginal();

    expect(fn () => app(ClientProvisioner::class)->provision(
        name: 'Adopted',
        redirectUris: ['https://app.test/login/callback'],
        adoptClientId: (string) $existing->getKey(),
        existingClientSecret: 'wrong-secret',
    ))->toThrow(FirstPartyClientProvisioningException::class, 'secret does not match');

    expect($existing->refresh()->getRawOriginal())->toBe($originalAttributes);
});

it('verifies the existing credential before rotating it', function (): void {
    $provisioner = app(ClientProvisioner::class);
    $created = $provisioner->provision('Original name', ['https://original.test/callback']);
    $originalSecret = Client::query()->findOrFail($created->client->key)->secret;

    expect(fn () => $provisioner->provision(
        name: 'Changed name',
        redirectUris: ['https://changed.test/callback'],
        rotateSecret: true,
        existingClientSecret: 'wrong-secret',
    ))->toThrow(FirstPartyClientProvisioningException::class, 'secret does not match');

    expect(Client::query()->findOrFail($created->client->key)->getAttribute('name'))->toBe('Original name')
        ->and(Client::query()->findOrFail($created->client->key)->secret)->toBe($originalSecret);

    $rotated = $provisioner->provision(
        name: 'Changed name',
        redirectUris: ['https://changed.test/callback'],
        rotateSecret: true,
        existingClientSecret: $created->clientSecret,
    );

    expect($rotated->secretRotated)->toBeTrue()
        ->and($rotated->clientSecret)->toBeString()->not->toBeEmpty()->not->toBe($created->clientSecret)
        ->and(Client::query()->findOrFail($rotated->client->key)->secret)->toBe($rotated->clientSecret);
});

it('rejects unsafe adoption targets', function (Closure $mutate, string $message): void {
    $client = app(ClientRepository::class)
        ->createAuthorizationCodeGrantClient('Unsafe', ['https://unsafe.test/callback']);
    $mutate($client, User::create(['name' => 'Owner', 'email' => 'owner@example.com', 'password' => 'secret']));

    expect(fn () => app(ClientProvisioner::class)->provision(
        'Unsafe',
        ['https://app.test/login/callback'],
        adoptClientId: (string) $client->getKey(),
    ))->toThrow(FirstPartyClientProvisioningException::class, $message);
})->with([
    'revoked' => [fn (Client $client) => $client->forceFill(['revoked_at' => now()])->save(), 'revoked'],
    'public' => [fn (Client $client) => $client->forceFill(['secret' => null])->save(), 'confidential'],
    'user-owned' => [fn (Client $client, User $owner) => $client->forceFill(['owner_type' => $owner::class, 'owner_id' => $owner->getKey()])->save(), 'must not be owned'],
]);

it('rejects exchange audiences when token exchange is disabled', function (): void {
    config(['oidc.clients.token_exchange' => false]);

    expect(fn () => app(ClientProvisioner::class)->provision(
        'First-party app',
        ['https://app.test/login/callback'],
        allowedExchangeAudiences: ['https://api.test/orders'],
    ))->toThrow(FirstPartyClientProvisioningException::class, 'disabled');

    expect(Client::query()->where('provisioning_key', 'first-party')->exists())->toBeFalse();
});

it('does not revoke existing tokens when rotating the client secret', function (): void {
    $provisioner = app(ClientProvisioner::class);
    $created = $provisioner->provision('First-party app', ['https://app.test/login/callback']);
    $token = AccessToken::factory()->create(['client_id' => $created->client->key, 'user_id' => null]);

    $provisioner->provision(
        'First-party app',
        ['https://app.test/login/callback'],
        rotateSecret: true,
    );

    expect($token->refresh()->isRevoked())->toBeFalse();
});

it('rejects invalid provisioning input before writing', function (
    string $name,
    array $redirectUris,
    array $audiences,
    string $message,
    array $postLogoutRedirectUris = [],
): void {
    expect(fn () => app(ClientProvisioner::class)->provision(
        $name,
        $redirectUris,
        postLogoutRedirectUris: $postLogoutRedirectUris,
        allowedExchangeAudiences: $audiences,
    ))->toThrow(FirstPartyClientProvisioningException::class, $message);

    expect(Client::query()->where('provisioning_key', 'first-party')->exists())
        ->toBeFalse();
})->with([
    'blank name' => [' ', ['https://app.test/callback'], [], 'name'],
    'missing redirect' => ['App', [], [], 'At least one redirect URI'],
    'redirect user info' => ['App', ['https://user@app.test/callback'], [], 'without user information'],
    'redirect fragment' => ['App', ['https://app.test/callback#fragment'], [], 'without user information or a fragment'],
    'redirect not an absolute http(s) uri' => ['App', ['https://app.test/call back'], [], 'absolute HTTP(S) URI'],
    'post logout not an absolute http(s) uri' => ['App', ['https://app.test/callback'], [], 'absolute HTTP(S) URI', ['https://app.test/logged out']],
    'relative audience' => ['App', ['https://app.test/callback'], ['/orders'], 'HTTP(S) URL or a urn: identifier'],
    'audience non-http scheme' => ['App', ['https://app.test/callback'], ['mailto:orders@example.com'], 'HTTP(S) URL or a urn: identifier'],
]);

it('accepts https and urn audience identifiers', function (): void {
    $result = app(ClientProvisioner::class)->provision(
        'First-party app',
        ['https://app.test/callback'],
        allowedExchangeAudiences: ['urn:example:orders', 'https://api.test/orders'],
    );

    expect($result->client->allowedAudiences)
        ->toBe(['urn:example:orders', 'https://api.test/orders']);
});

it('rejects adoption when another managed client already exists', function (): void {
    $provisioner = app(ClientProvisioner::class);
    $managed = $provisioner->provision('Managed', ['https://managed.test/callback']);
    $other = app(ClientRepository::class)
        ->createAuthorizationCodeGrantClient('Other', ['https://other.test/callback']);

    expect(fn () => $provisioner->provision(
        'Other',
        ['https://other.test/callback'],
        adoptClientId: (string) $other->getKey(),
    ))->toThrow(FirstPartyClientProvisioningException::class, 'different client');

    expect(Client::query()->findOrFail($managed->client->key)->getRawOriginal('provisioning_key'))->toBe('first-party')
        ->and($other->refresh()->getRawOriginal('provisioning_key'))->toBeNull();
});

it('normalizes metadata and removes exchange capability when audiences become empty', function (): void {
    $provisioner = app(ClientProvisioner::class);
    $provisioner->provision(
        ' First-party app ',
        [' https://app.test/second ', 'https://app.test/first', 'https://app.test/second'],
        [' https://app.test/second ', 'https://app.test/first', 'https://app.test/second'],
        [' https://api.test/second ', 'https://api.test/first', 'https://api.test/second'],
    );

    $normalized = Client::query()
        ->where('provisioning_key', 'first-party')
        ->firstOrFail();

    expect($normalized->getAttribute('name'))->toBe('First-party app')
        ->and($normalized->getAttribute('redirect_uris'))->toBe(['https://app.test/second', 'https://app.test/first'])
        ->and(json_decode((string) $normalized->getRawOriginal('post_logout_redirect_uris'), true, flags: JSON_THROW_ON_ERROR))
        ->toBe(['https://app.test/second', 'https://app.test/first'])
        ->and(json_decode((string) $normalized->getRawOriginal('allowed_exchange_audiences'), true, flags: JSON_THROW_ON_ERROR))
        ->toBe(['https://api.test/second', 'https://api.test/first']);

    $result = $provisioner->provision('First-party app', ['https://app.test/callback']);

    expect($result->client->redirectUris)->toBe(['https://app.test/callback'])
        ->and($result->client->grantTypes)->toBe(['authorization_code', 'refresh_token'])
        ->and($result->client->allowedAudiences)->toBe([]);
});

it('rolls back a created client by deleting it, never an adopted or reconciled one', function (): void {
    $provisioner = app(ClientProvisioner::class);
    $created = $provisioner->provision('First-party app', ['https://app.test/login/callback']);

    $reconciled = $provisioner->provision('First-party app', ['https://app.test/login/callback']);

    config(['oidc.realm' => 'another-realm']);

    $provisioner->rollback($reconciled);
    expect(Client::query()->find($created->client->key))->not->toBeNull();

    $provisioner->rollback($created);
    expect(Client::query()->find($created->client->key))->toBeNull();
});

it('provisions the first-party client with the realm scope assignment', function (): void {
    config(['oidc.clients.default_scopes' => ['openid'], 'oidc.clients.optional_scopes' => ['profile']]);

    $result = app(ClientProvisioner::class)->provision('App', ['https://app.test/callback']);

    expect($result->client->defaultScopeAssignments)->toBe(['openid'])
        ->and($result->client->optionalScopeAssignments)->toBe(['profile']);
});

it('applies explicit scope lists on provisioning and keeps them on reconciliation', function (): void {
    $provisioner = app(ClientProvisioner::class);

    $created = $provisioner->provision('App', ['https://app.test/callback'], defaultScopes: ['openid'], optionalScopes: ['email']);
    $kept = $provisioner->provision('App', ['https://app.test/callback']);
    $changed = $provisioner->provision('App', ['https://app.test/callback'], optionalScopes: ['*']);

    expect($created->client->defaultScopeAssignments)->toBe(['openid'])
        ->and($created->client->optionalScopeAssignments)->toBe(['email'])
        ->and($kept->client->optionalScopeAssignments)->toBe(['email'])
        ->and($changed->client->defaultScopeAssignments)->toBe(['openid'])
        ->and($changed->client->optionalScopeAssignments)->toBe(['*']);
});

it('redacts the existing client credential from exception traces', function (): void {
    app(ClientProvisioner::class)->provision(name: 'First-party app', redirectUris: ['https://app.test/login/callback']);
    $existingClientSecret = 'trace-secret-that-must-be-redacted';

    try {
        app(ClientProvisioner::class)->provision(
            name: 'First-party app',
            redirectUris: ['https://app.test/login/callback'],
            existingClientSecret: $existingClientSecret,
        );
    } catch (FirstPartyClientProvisioningException $exception) {
        $traceContainsSecret = false;

        foreach ($exception->getTrace() as $frame) {
            $arguments = $frame['args'] ?? [];

            array_walk_recursive(
                $arguments,
                function (mixed $argument) use (&$traceContainsSecret, $existingClientSecret): void {
                    $traceContainsSecret = $traceContainsSecret || $argument === $existingClientSecret;
                },
            );
        }

        expect($traceContainsSecret)->toBeFalse();

        return;
    }

    test()->fail('Expected credential verification to fail.');
});
