<?php

declare(strict_types=1);

use Lock\Server\Clients\ClientRepository;
use Lock\Server\Shared\Clients\Client;
use Lock\Server\Shared\Scopes\Scope;
use Lock\Server\Shared\Scopes\ScopeParameterPolicy;
use Lock\Server\Shared\Scopes\ScopeRepository;

beforeEach(function (): void {
    config(['oidc.scopes' => ['organization:{organization}' => 'Act within organization {organization}']]);
});

function allowScopeParametersFor(string $userIdentifier): void
{
    app()->instance(ScopeParameterPolicy::class, new readonly class($userIdentifier) implements ScopeParameterPolicy
    {
        public function __construct(private string $member) {}

        public function allows(Scope $scope, string $grantType, ?Client $client, ?string $userIdentifier, array $audiences): bool
        {
            return $scope->parameter === 'acme' && $userIdentifier === $this->member;
        }
    });
}

it('expands a template into the concrete scope a request names', function (): void {
    $scope = app(ScopeRepository::class)->find('organization:acme');

    expect($scope?->id)->toBe('organization:acme')
        ->and($scope?->description)->toBe('Act within organization acme')
        ->and($scope?->template)->toBe('organization:{organization}')
        ->and($scope?->parameter)->toBe('acme')
        ->and(app(ScopeRepository::class)->all()->pluck('id'))->not->toContain('organization:{organization}');
});

it('resolves the template itself as an open scope that is never granted', function (): void {
    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/callback']);
    $client->forceFill(['optional_scopes' => ['openid', 'organization:{organization}']])->save();

    expect(app(ScopeRepository::class)->find('organization:{organization}')?->isOpen())->toBeTrue()
        ->and(app(ScopeRepository::class)->grant(['openid', 'organization:{organization}'], 'authorization_code', $client->snapshot(), 'member'))->toBe(['openid']);
});

it('matches no scope for a value outside the scope-token grammar', function (string $requested): void {
    expect(app(ScopeRepository::class)->find($requested))->toBeNull();
})->with(['organization:', 'organization:{acme}', 'organization:ac"me', 'organization:ac\me', 'team:acme']);

it('lets a client assigned the template request any value of it', function (): void {
    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/callback']);
    $client->forceFill(['default_scopes' => ['openid'], 'optional_scopes' => ['organization:{organization}']])->save();

    expect($client->snapshot()->allowsScope('organization:acme'))->toBeTrue()
        ->and($client->snapshot()->allowsScope('team:acme'))->toBeFalse();
});

it('grants a parameterized scope to a user only when the host policy allows its value', function (): void {
    allowScopeParametersFor('member');
    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/callback']);
    $client->forceFill(['optional_scopes' => ['openid', 'organization:{organization}']])->save();
    $scopes = app(ScopeRepository::class);

    expect($scopes->grant(['openid', 'organization:acme'], 'authorization_code', $client->snapshot(), 'member'))->toBe(['openid', 'organization:acme'])
        ->and($scopes->grant(['openid', 'organization:acme'], 'authorization_code', $client->snapshot(), 'stranger'))->toBe(['openid'])
        ->and($scopes->grant(['openid', 'organization:globex'], 'refresh_token', $client->snapshot(), 'member'))->toBe(['openid']);
});

it('issues a machine client only the value assigned to it unless a host policy says otherwise', function (): void {
    app(ClientRepository::class)->create('Service account', ['client_credentials'], clientId: 'bound', secret: 'secret', defaultScopes: ['organization:acme'], optionalScopes: []);
    app(ClientRepository::class)->create('Any organization', ['client_credentials'], clientId: 'unbound', secret: 'secret', defaultScopes: [], optionalScopes: ['organization:{organization}']);

    $token = fn (string $clientId, array $extra = []) => $this->post('/oauth/token', ['grant_type' => 'client_credentials', 'client_id' => $clientId, 'client_secret' => 'secret', ...$extra]);

    $token('bound')->assertOk()->assertJsonPath('scope', 'organization:acme');
    $token('bound', ['scope' => 'organization:globex'])->assertStatus(400)->assertJsonPath('error', 'invalid_scope');
    expect($token('unbound', ['scope' => 'organization:acme'])->assertOk()->json('scope'))->toBeNull();
});
