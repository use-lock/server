<?php

declare(strict_types=1);

use Lock\Server\Clients\ClientRepository;
use Lock\Server\Shared\Clients\Client;
use Lock\Server\Shared\Scopes\Scope;
use Lock\Server\Shared\Scopes\ScopeGrantFilter;
use Lock\Server\Shared\Scopes\ScopeRepository;

beforeEach(function (): void {
    config(['oidc.scopes' => ['orders:read' => 'Read orders', 'orders:write' => 'Write orders']]);
});

function filterScopesTo(string ...$kept): void
{
    app()->instance(ScopeGrantFilter::class, new readonly class($kept) implements ScopeGrantFilter
    {
        /** @param  list<string>  $kept */
        public function __construct(private array $kept) {}

        public function filter(array $scopes, string $grantType, ?Client $client, ?string $userIdentifier, array $audiences): array
        {
            return [
                ...array_values(array_filter($scopes, fn (Scope $scope): bool => in_array($scope->id, $this->kept, true))),
                new Scope('orders:admin'),
            ];
        }
    });
}

it('narrows the granted scopes to what the host filter keeps', function (string $grantType): void {
    filterScopesTo('openid', 'orders:read');
    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/callback']);

    expect(app(ScopeRepository::class)->grant(['openid', 'orders:read', 'orders:write'], $grantType, $client->snapshot(), 'member'))
        ->toBe(['openid', 'orders:read']);
})->with(['authorization_code', 'refresh_token', 'urn:ietf:params:oauth:grant-type:token-exchange']);

it('never widens the grant with a scope the filter adds', function (): void {
    filterScopesTo('openid');
    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/callback']);

    expect(app(ScopeRepository::class)->grant(['openid'], 'authorization_code', $client->snapshot(), 'member'))->toBe(['openid']);
});

it('narrows a machine client token as well', function (): void {
    filterScopesTo('orders:read');
    app(ClientRepository::class)->create('M2M', ['client_credentials'], clientId: 'm2m', secret: 'secret', defaultScopes: ['orders:read', 'orders:write'], optionalScopes: []);

    $this->post('/oauth/token', ['grant_type' => 'client_credentials', 'client_id' => 'm2m', 'client_secret' => 'secret'])
        ->assertOk()
        ->assertJsonPath('scope', 'orders:read');
});
