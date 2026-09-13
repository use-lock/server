<?php

declare(strict_types=1);

/**
 * RFC 7591 §2 (client metadata), §3.1 (registration request), §3.2 (response, errors); OIDC RP-Initiated Logout §3 and
 * Back-Channel Logout §2.2 (logout metadata)
 */

use Lock\Server\Clients\Models\Client;

/**
 * @param  array<string, mixed>  $overrides
 */
function enableDynamicClientRegistration(array $overrides = []): void
{
    config(['oidc.clients.registration' => [
        'enabled' => true,
        'allowed_redirect_schemes' => [],
        'allowed_redirect_domains' => ['*'],
        ...$overrides,
    ]]);

    reloadOidcRoutes();
}

it('answers 404 while dynamic registration is disabled for the realm', function (): void {
    $this->postJson('/oauth/register', ['redirect_uris' => ['https://rp.test/cb']])->assertNotFound();
});

it('registers a public client and returns the RFC 7591 response', function (): void {
    enableDynamicClientRegistration();

    $response = $this->postJson('/oauth/register', [
        'client_name' => 'Agent',
        'redirect_uris' => ['https://agent.test/callback'],
    ])->assertCreated();

    $response->assertJson([
        'client_name' => 'Agent',
        'redirect_uris' => ['https://agent.test/callback'],
        'post_logout_redirect_uris' => [],
        'response_types' => ['code'],
        'token_endpoint_auth_method' => 'none',
    ]);

    // RFC 7591 §3.2.1: client_secret_expires_at accompanies an issued secret only
    expect($response->json('client_id'))->toBeString()->not->toBeEmpty()
        ->and($response->json('client_id_issued_at'))->toBeInt()
        ->and($response->json('grant_types'))->toBe(['authorization_code', 'refresh_token'])
        ->and($response->json())->not->toHaveKeys(['client_secret', 'client_secret_expires_at', 'backchannel_logout_uri'])
        ->and(Client::query()->whereKey($response->json('client_id'))->firstOrFail()->snapshot()->confidential)->toBeFalse();

    $this->postJson('/oauth/register', ['redirect_uris' => ['https://agent.test/callback']])
        ->assertCreated()
        ->assertJsonPath('client_name', 'agent.test');
});

it('assigns the realm default and optional scopes to a registered client and echoes them', function (): void {
    enableDynamicClientRegistration();
    config(['oidc.clients.default_scopes' => ['openid'], 'oidc.clients.optional_scopes' => ['mcp:use']]);

    $response = $this->postJson('/oauth/register', [
        'redirect_uris' => ['https://agent.test/callback'],
    ])->assertCreated()->assertJsonPath('scope', 'openid mcp:use');

    $client = Client::query()->whereKey($response->json('client_id'))->firstOrFail();

    expect($client->default_scopes)->toBe(['openid'])
        ->and($client->optional_scopes)->toBe(['mcp:use']);
});

it('omits scope from the response while the client may request every scope', function (): void {
    enableDynamicClientRegistration();

    $this->postJson('/oauth/register', ['redirect_uris' => ['https://agent.test/callback']])
        ->assertCreated()
        ->assertJsonMissingPath('scope');
});

// RFC 7591 §2, §3.2.1 — a secret-based auth method registers a confidential client; the secret is returned once
it('issues a secret to a client registering a secret-based token_endpoint_auth_method', function (string $method): void {
    enableDynamicClientRegistration();

    $response = $this->postJson('/oauth/register', [
        'redirect_uris' => ['https://agent.test/callback'],
        'token_endpoint_auth_method' => $method,
    ])->assertCreated()
        ->assertJsonPath('token_endpoint_auth_method', $method)
        ->assertJsonPath('client_secret_expires_at', 0);

    $client = Client::query()->whereKey($response->json('client_id'))->firstOrFail();

    expect($response->json('client_secret'))->toBeString()->not->toBeEmpty()
        ->and($client->snapshot()->confidential)->toBeTrue()
        ->and($client->token_endpoint_auth_method->value)->toBe($method)
        ->and($client->secret)->toBe($response->json('client_secret'));
})->with(['client_secret_basic', 'client_secret_post']);

// RFC 7591 §2 — grant_types ⊆ {authorization_code, refresh_token}, response_types == [code]
it('rejects client metadata this endpoint does not provision', function (array $metadata): void {
    enableDynamicClientRegistration();

    $this->postJson('/oauth/register', ['redirect_uris' => ['https://rp.test/cb'], ...$metadata])
        ->assertBadRequest()
        ->assertJsonPath('error', 'invalid_client_metadata');

    expect(Client::query()->count())->toBe(0);
})->with([
    'unsupported auth method' => [['token_endpoint_auth_method' => 'private_key_jwt']],
    'foreign grant' => [['grant_types' => ['authorization_code', 'implicit']]],
    'empty grants' => [['grant_types' => []]],
    'refresh only' => [['grant_types' => ['refresh_token']]],
    'grants not a list' => [['grant_types' => 'authorization_code']],
    'foreign response type' => [['response_types' => ['token']]],
    'empty response types' => [['response_types' => []]],
    'http backchannel_logout_uri' => [['backchannel_logout_uri' => 'http://rp.test/backchannel']],
    'backchannel_logout_uri with fragment' => [['backchannel_logout_uri' => 'https://rp.test/backchannel#x']],
    'relative backchannel_logout_uri' => [['backchannel_logout_uri' => '/backchannel']],
    'backchannel credentials' => [['backchannel_logout_uri' => 'https://user:secret@rp.test/logout']],
    'backchannel loopback' => [['backchannel_logout_uri' => 'https://127.0.0.1/logout']],
    'backchannel private network' => [['backchannel_logout_uri' => 'https://10.0.0.1/logout']],
    'backchannel metadata service' => [['backchannel_logout_uri' => 'https://169.254.169.254/logout']],
    'backchannel IPv6 loopback' => [['backchannel_logout_uri' => 'https://[::1]/logout']],
    'backchannel IPv4 mapped address' => [['backchannel_logout_uri' => 'https://[::ffff:127.0.0.1]/logout']],
    'backchannel alternate IPv4' => [['backchannel_logout_uri' => 'https://2130706433/logout']],
    'post_logout_redirect_uris not a list' => [['post_logout_redirect_uris' => 'https://rp.test/out']],
]);

it('registers the grant types a client asks for', function (): void {
    enableDynamicClientRegistration();

    $response = $this->postJson('/oauth/register', [
        'redirect_uris' => ['https://rp.test/cb'],
        'grant_types' => ['authorization_code'],
        'response_types' => ['code'],
    ])->assertCreated()->assertJsonPath('grant_types', ['authorization_code']);

    expect(Client::query()->whereKey($response->json('client_id'))->firstOrFail()->grant_types)->toBe(['authorization_code']);
});

it('persists and echoes the logout metadata', function (): void {
    enableDynamicClientRegistration();

    $response = $this->postJson('/oauth/register', [
        'redirect_uris' => ['https://rp.test/cb'],
        'post_logout_redirect_uris' => ['https://rp.test/logged-out', 'https://rp.test/logged-out'],
        'backchannel_logout_uri' => 'https://rp.test/backchannel?tenant=1',
        'backchannel_logout_session_required' => true,
    ])->assertCreated()->assertJson([
        'post_logout_redirect_uris' => ['https://rp.test/logged-out'],
        'backchannel_logout_uri' => 'https://rp.test/backchannel?tenant=1',
        'backchannel_logout_session_required' => true,
    ]);

    $client = Client::query()->whereKey($response->json('client_id'))->firstOrFail();

    expect($client->post_logout_redirect_uris)->toBe(['https://rp.test/logged-out'])
        ->and($client->backchannel_logout_uri)->toBe('https://rp.test/backchannel?tenant=1')
        ->and($client->backchannel_logout_session_required)->toBeTrue();
});

it('rejects a missing or empty redirect uri list', function (): void {
    enableDynamicClientRegistration();

    $this->postJson('/oauth/register', ['client_name' => 'X'])
        ->assertBadRequest()
        ->assertJsonPath('error', 'invalid_client_metadata');

    $this->postJson('/oauth/register', ['redirect_uris' => []])
        ->assertBadRequest()
        ->assertJsonPath('error', 'invalid_client_metadata');

    expect(Client::query()->count())->toBe(0);
});

it('rejects malformed redirect uris', function (string $uri): void {
    enableDynamicClientRegistration();

    $this->postJson('/oauth/register', ['redirect_uris' => [$uri]])
        ->assertBadRequest()
        ->assertJsonPath('error', 'invalid_redirect_uri');

    expect(Client::query()->count())->toBe(0);
})->with([
    'fragment' => 'https://rp.test/cb#fragment',
    'userinfo' => 'https://user:pass@rp.test/cb',
    'no host' => 'https:///cb',
    'control characters' => "https://rp.test/cb\x01",
    'relative' => '/callback',
]);

it('rejects custom schemes unless allow-listed', function (): void {
    enableDynamicClientRegistration();

    $this->postJson('/oauth/register', ['redirect_uris' => ['myapp://auth/callback']])
        ->assertBadRequest()
        ->assertJsonPath('error', 'invalid_redirect_uri');

    enableDynamicClientRegistration(['allowed_redirect_schemes' => ['myapp']]);

    $this->postJson('/oauth/register', ['redirect_uris' => ['myapp://auth/callback']])
        ->assertCreated();

    $this->postJson('/oauth/register', ['redirect_uris' => ['myapp:/callback']])
        ->assertBadRequest()
        ->assertJsonPath('error', 'invalid_redirect_uri');
});

it('enforces the redirect domain allowlist for redirect and post-logout uris', function (): void {
    enableDynamicClientRegistration(['allowed_redirect_domains' => ['rp.test']]);

    $this->postJson('/oauth/register', ['redirect_uris' => ['https://rp.test/cb']])
        ->assertCreated();

    $this->postJson('/oauth/register', ['redirect_uris' => ['https://evil.test/cb']])
        ->assertBadRequest()
        ->assertJsonPath('error', 'invalid_redirect_uri');

    $this->postJson('/oauth/register', [
        'redirect_uris' => ['https://rp.test/cb'],
        'post_logout_redirect_uris' => ['https://evil.test/out'],
    ])->assertBadRequest()->assertJsonPath('error', 'invalid_client_metadata');
});
