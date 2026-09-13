<?php

declare(strict_types=1);

/**
 * RFC 8707 §2 (resource indicators), RFC 9728 §3 (protected resource metadata)
 */

use Illuminate\Support\Collection;
use Lock\Server\Realms\ConfiguredRealm;
use Lock\Server\Scopes\ConfiguredScopeRepository;
use Lock\Server\Shared\Realms\Realm;
use Lock\Server\Shared\Realms\RealmAudiences;
use Lock\Server\Shared\Realms\RealmResolver;
use Lock\Server\Shared\Scopes\Scope;
use Lock\Server\Shared\Scopes\ScopeCatalog;
use Lock\Server\Shared\Scopes\ScopeRepository;

class RepositoryClassCatalog implements ScopeCatalog
{
    public function scopes(array $audiences): array
    {
        return array_merge(...array_map(
            fn (string $audience): array => [$audience.'/read' => "Read {$audience} things"],
            $audiences,
        ));
    }
}

class RepositoryThrowingCatalog implements ScopeCatalog
{
    public function scopes(array $audiences): array
    {
        throw new RuntimeException('database is away');
    }
}

class RepositoryRealmCatalog implements ScopeCatalog
{
    public function scopes(array $audiences): array
    {
        $realm = app(RealmResolver::class)->current()->identifier();

        return ["{$realm}:read" => "Read {$realm} things"];
    }
}

class RepositorySwitchableRealmResolver implements RealmResolver
{
    public function __construct(public string $realm) {}

    public function current(): Realm
    {
        return new ConfiguredRealm($this->realm);
    }
}

beforeEach(function (): void {
    config(['app.url' => 'https://op.test', 'oidc.issuer' => null]);
});

function freshScopeRepository(): ScopeRepository
{
    return new ConfiguredScopeRepository(app(), app(RealmResolver::class), app(RealmAudiences::class));
}

/**
 * @param  list<string>  $audiences
 * @return list<string>
 */
function scopeIds(array $audiences = []): array
{
    return freshScopeRepository()->all($audiences)->map(fn (Scope $scope): string => $scope->id)->all();
}

it('exposes the configured catalog plus the oidc standard scopes, preferring the catalog description', function (): void {
    config(['oidc.scopes' => ['project:update' => 'Update projects', 'openid' => 'Custom openid description']]);

    $repository = freshScopeRepository();

    expect(scopeIds())->toContain('project:update', 'openid', 'profile', 'email')
        ->and($repository->all()->filter(fn (Scope $scope): bool => $scope->id === 'openid'))->toHaveCount(1)
        ->and($repository->find('openid')?->description)->toBe('Custom openid description')
        ->and($repository->find('nope'))->toBeNull();
});

it('hands a scope a resource owns to that resource alone, never to the realm default audience', function (): void {
    config([
        'oidc.scopes' => ['project:update' => 'Update projects', 'mcp:use' => 'Use the MCP server'],
        'oidc.resources' => ['mcp' => ['scopes' => ['mcp:use']]],
    ]);

    $repository = freshScopeRepository();

    expect($repository->find('mcp:use'))->toBeNull()
        ->and($repository->find('project:update'))->not->toBeNull()
        ->and($repository->find('mcp:use', ['https://op.test/mcp'])?->description)->toBe('Use the MCP server')
        ->and($repository->find('project:update', ['https://op.test/mcp']))->toBeNull();
});

it('reads the same scope value under two resources as two different scopes', function (): void {
    config([
        'oidc.scopes' => ['read' => 'Read things'],
        'oidc.resources' => [
            'mcp' => ['scopes' => ['read']],
            'https://api.example/orders' => ['scopes' => ['read']],
        ],
    ]);

    $repository = freshScopeRepository();

    expect($repository->find('read'))->toBeNull()
        ->and($repository->find('read', ['https://op.test/mcp']))->not->toBeNull()
        ->and($repository->find('read', ['https://api.example/orders']))->not->toBeNull()
        ->and($repository->find('read', ['https://api.example/invoices']))->toBeNull();
});

it('offers the oidc standard scopes under every audience', function (): void {
    config(['oidc.resources' => ['mcp' => ['scopes' => ['mcp:use']]]]);

    expect(scopeIds(['https://op.test/mcp']))->toContain('openid', 'profile', 'email', 'mcp:use');
});

it('offers a scope a resource declares even when the catalog does not describe it', function (): void {
    config(['oidc.resources' => ['mcp' => ['scopes' => ['mcp:use']]]]);

    expect(freshScopeRepository()->find('mcp:use', ['https://op.test/mcp'])?->description)->toBe('');
});

it('resolves a class-string catalog from the container, asking it for the requested resources', function (): void {
    config()->set('oidc.scopes', RepositoryClassCatalog::class);

    expect(scopeIds())->toContain('https://op.test/read')
        ->and(scopeIds(['https://api.example/orders']))->toContain('https://api.example/orders/read')
        ->not->toContain('https://op.test/read');

    config()->set('oidc.scopes', stdClass::class);

    expect(fn (): Collection => freshScopeRepository()->all())->toThrow(LogicException::class);
});

it('caches the catalog per realm on one instance', function (): void {
    config()->set('oidc.scopes', RepositoryRealmCatalog::class);
    $resolver = new RepositorySwitchableRealmResolver('acme');
    app()->instance(RealmResolver::class, $resolver);
    $repository = new ConfiguredScopeRepository(app(), $resolver, app(RealmAudiences::class));

    expect($repository->find('acme:read'))->not->toBeNull();

    $resolver->realm = 'globex';

    expect($repository->find('globex:read'))->not->toBeNull()
        ->and($repository->find('acme:read'))->toBeNull();

    $resolver->realm = 'acme';

    expect($repository->find('acme:read'))->not->toBeNull();
});

it('falls back to the standard scopes when the catalog throws', function (): void {
    config()->set('oidc.scopes', RepositoryThrowingCatalog::class);

    expect(scopeIds())->toContain('openid')->not->toContain('catalog:read');
});
