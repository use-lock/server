<?php

declare(strict_types=1);

/**
 * RFC 9728 §3 (protected resource metadata)
 */
it('serves metadata for a configured protected resource', function (): void {
    config([
        'app.url' => 'https://op.test',
        'oidc.issuer' => null,
        'oidc.resources' => ['mcp' => ['scopes' => ['mcp:use']]],
    ]);

    $this->getJson('/.well-known/oauth-protected-resource/mcp')
        ->assertOk()
        ->assertHeader('Cache-Control', 'max-age=3600, public')
        ->assertExactJson([
            'resource' => 'https://op.test/mcp',
            'authorization_servers' => ['https://op.test'],
            'scopes_supported' => ['mcp:use'],
            'bearer_methods_supported' => ['header'],
        ]);
});

it('builds the resource identifier from the configured issuer, serving the issuer root for an empty path', function (): void {
    config([
        'oidc.issuer' => 'https://id.example.com/',
        'oidc.resources' => ['mcp' => ['scopes' => []], '' => ['scopes' => ['api']]],
    ]);

    $this->getJson('/.well-known/oauth-protected-resource/mcp')
        ->assertOk()
        ->assertJsonPath('resource', 'https://id.example.com/mcp')
        ->assertJsonPath('authorization_servers.0', 'https://id.example.com');

    $this->getJson('/.well-known/oauth-protected-resource')
        ->assertOk()
        ->assertJsonPath('resource', 'https://id.example.com');
});

it('answers 404 for resources that are not configured', function (): void {
    config(['oidc.resources' => ['mcp' => ['scopes' => []]]]);

    $this->getJson('/.well-known/oauth-protected-resource/unknown')->assertNotFound();
    $this->getJson('/.well-known/oauth-protected-resource')->assertNotFound();
});
