<?php

declare(strict_types=1);

/**
 * OpenID Connect Discovery 1.0 §3 + RFC 8414 §2 (authorization server metadata); RFC 8693 / RFC 7591 (advertised when enabled)
 */

use Lock\Server\Tests\FeatureTestCase;

it('serves a spec-compliant discovery document', function (): void {
    config(['app.url' => 'https://op.test', 'oidc.issuer' => null]);

    $response = $this->getJson('/.well-known/openid-configuration')
        ->assertOk()
        ->assertHeader('Cache-Control', 'max-age=3600, public');

    $response->assertJson([
        'issuer' => 'https://op.test',
        'response_types_supported' => ['code'],
        'response_modes_supported' => ['query'],
        'subject_types_supported' => ['public'],
        'id_token_signing_alg_values_supported' => ['RS256'],
        'code_challenge_methods_supported' => ['S256'],
        'token_endpoint_auth_methods_supported' => ['client_secret_basic', 'client_secret_post', 'none'],
        'introspection_endpoint_auth_methods_supported' => ['client_secret_basic', 'client_secret_post'],
        'revocation_endpoint_auth_methods_supported' => ['client_secret_basic', 'client_secret_post', 'none'],
        'claims_parameter_supported' => false,
        'request_parameter_supported' => false,
        'request_uri_parameter_supported' => false,
        'authorization_response_iss_parameter_supported' => true,
        'backchannel_logout_supported' => true,
        'backchannel_logout_session_supported' => true,
    ]);

    expect($response->json('authorization_endpoint'))->toBe('https://op.test/oauth/authorize')
        ->and($response->json('token_endpoint'))->toBe('https://op.test/oauth/token')
        ->and($response->json('jwks_uri'))->toBe('https://op.test/.well-known/jwks.json')
        ->and($response->json('scopes_supported'))->toContain('openid', 'profile', 'email')
        ->and($response->json('grant_types_supported'))->toContain('authorization_code', 'refresh_token', 'client_credentials')
        ->and($response->json('claims_supported'))->toContain('acr', 'amr', 'sid');
});

it('builds the issuer and every endpoint from the configured issuer host, trimming a trailing slash', function (): void {
    config(['oidc.issuer' => 'https://id.example.com/', 'app.url' => 'https://app.internal']);

    $doc = $this->getJson('/.well-known/openid-configuration')->assertOk();

    expect($doc->json('issuer'))->toBe('https://id.example.com')
        ->and($doc->json('authorization_endpoint'))->toStartWith('https://id.example.com/')
        ->and($doc->json('token_endpoint'))->toStartWith('https://id.example.com/')
        ->and($doc->json('jwks_uri'))->toStartWith('https://id.example.com/')
        ->and($doc->json('userinfo_endpoint'))->toStartWith('https://id.example.com/');
});

// OIDC Discovery 1.0 §3 — acr_values_supported follows the realm mapping
it('advertises the realm acr values', function (): void {
    config(['oidc.login.acr_single_factor' => 'urn:example:loa:1', 'oidc.login.acr_multi_factor' => 'urn:example:loa:2']);

    expect($this->getJson('/.well-known/openid-configuration')->json('acr_values_supported'))
        ->toBe(['urn:example:loa:1', 'urn:example:loa:2']);
});

it('advertises token exchange and dynamic registration only while enabled', function (): void {
    $doc = $this->getJson('/.well-known/openid-configuration')->assertOk();

    expect($doc->json('grant_types_supported'))->toContain(FeatureTestCase::TOKEN_EXCHANGE_GRANT)
        ->and($doc->json())->not->toHaveKey('registration_endpoint');

    config(['oidc.clients.token_exchange' => false, 'oidc.clients.registration.enabled' => true]);
    reloadOidcRoutes();

    $doc = $this->getJson('/.well-known/openid-configuration')->assertOk();

    expect($doc->json('grant_types_supported'))->not->toContain(FeatureTestCase::TOKEN_EXCHANGE_GRANT)
        ->and($doc->json('registration_endpoint'))->toContain('/oauth/register');
});

it('advertises the union of the realm scopes and every registered resource scope', function (): void {
    config([
        'oidc.scopes' => ['realm:admin' => 'Administer the realm', 'orders:read' => 'Read orders'],
        'oidc.resources' => ['mcp' => ['scopes' => ['mcp:use']], 'https://api.internal/orders' => ['scopes' => ['orders:read']]],
    ]);

    expect($this->getJson('/.well-known/openid-configuration')->assertOk()->json('scopes_supported'))
        ->toContain('openid', 'profile', 'email', 'realm:admin', 'orders:read', 'mcp:use');
});
