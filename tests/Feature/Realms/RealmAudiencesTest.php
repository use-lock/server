<?php

declare(strict_types=1);

/**
 * RFC 9068 §3 (default resource indicator), §4 (aud); RFC 9728 §3.3 (protected resource identifiers)
 */

use Lock\Server\Shared\Realms\RealmAudiences;

beforeEach(function (): void {
    config(['app.url' => 'https://op.test', 'oidc.issuer' => null]);
});

it('addresses tokens to the realm issuer by default, whatever resources are registered', function (): void {
    config(['oidc.resources' => ['https://api.example/orders' => [], 'mcp' => ['scopes' => ['mcp:use']]]]);

    expect(app(RealmAudiences::class)->default())->toBe(['https://op.test']);
});

it('accepts the issuer plus every registered resource, path-relative ones resolved against the issuer', function (): void {
    config(['oidc.resources' => ['https://api.example/orders' => [], 'mcp' => ['scopes' => []], '' => ['scopes' => []]]]);

    $audiences = app(RealmAudiences::class);

    expect($audiences->all())->toBe(['https://op.test', 'https://api.example/orders', 'https://op.test/mcp'])
        ->and($audiences->protectedResource('mcp'))->toBe('https://op.test/mcp')
        ->and($audiences->protectedResource(''))->toBe('https://op.test');
});

it('accepts an audience naming one of them and rejects any other', function (): void {
    config(['oidc.resources' => ['https://api.example/orders' => []]]);

    $audiences = app(RealmAudiences::class);

    expect($audiences->accepts(['https://api.example/orders', 'https://elsewhere.example']))->toBeTrue()
        ->and($audiences->accepts(['https://op.test']))->toBeTrue()
        ->and($audiences->accepts(['https://elsewhere.example']))->toBeFalse()
        ->and($audiences->accepts(['some-client-id']))->toBeFalse()
        ->and($audiences->accepts([]))->toBeFalse();
});

it('advertises scopes for path-relative resources only', function (): void {
    config(['oidc.resources' => ['mcp' => ['scopes' => ['mcp:use']], 'https://api.example/orders' => ['scopes' => ['orders:read']]]]);

    $audiences = app(RealmAudiences::class);

    expect($audiences->advertisedScopes('mcp'))->toBe(['mcp:use'])
        ->and($audiences->advertisedScopes('/mcp/'))->toBe(['mcp:use'])
        ->and($audiences->advertisedScopes('orders'))->toBeNull()
        ->and($audiences->advertisedScopes(''))->toBeNull();
});

it('reads an absent resource parameter as the realm itself', function (): void {
    config(['oidc.resources' => ['mcp' => ['scopes' => []]]]);

    $audiences = app(RealmAudiences::class);

    expect($audiences->resolve([]))->toBe(['https://op.test'])
        ->and($audiences->resolve(['https://op.test/mcp']))->toBe(['https://op.test/mcp']);
});

it('reports the scopes the given resources own, and every scope some resource claims', function (): void {
    config(['oidc.resources' => [
        'mcp' => ['scopes' => ['mcp:use', 'read']],
        'https://api.example/orders' => ['scopes' => ['read']],
    ]]);

    $audiences = app(RealmAudiences::class);

    expect($audiences->declaredScopes(['https://op.test/mcp']))->toBe(['mcp:use', 'read'])
        ->and($audiences->declaredScopes(['https://api.example/orders']))->toBe(['read'])
        ->and($audiences->declaredScopes(['https://op.test']))->toBe([])
        ->and($audiences->claimedScopes())->toBe(['mcp:use', 'read']);
});
