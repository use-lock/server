<?php

declare(strict_types=1);

/**
 * RFC 8414 §3 (authorization server metadata well-known path, path-insertion form)
 */
it('serves the same document as the openid configuration under both well-known forms', function (): void {
    config(['oidc.issuer' => 'https://id.example.com']);

    $oidc = $this->getJson('/.well-known/openid-configuration')->assertOk()->json();

    $this->getJson('/.well-known/oauth-authorization-server')
        ->assertOk()
        ->assertHeader('Cache-Control', 'max-age=3600, public')
        ->assertExactJson($oidc);

    $this->getJson('/.well-known/oauth-authorization-server/mcp')
        ->assertOk()
        ->assertJsonPath('issuer', 'https://id.example.com');
});
