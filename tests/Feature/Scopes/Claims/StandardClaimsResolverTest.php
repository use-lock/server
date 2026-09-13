<?php

declare(strict_types=1);

/**
 * OpenID Connect Core 1.0 §5.1 (standard claims), §5.4 (scope → claims mapping)
 */

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Lock\Server\Scopes\Claims\StandardClaimsResolver;
use Lock\Server\Shared\Scopes\ClaimsAudience;
use Lock\Server\Shared\Scopes\ClaimsRequest;
use Workbench\App\Models\User;

/**
 * @param  list<string>  $scopes
 * @return array<string, mixed>
 */
function standardClaims(Authenticatable $user, array $scopes): array
{
    return (new StandardClaimsResolver)->resolve(new ClaimsRequest(
        user: $user,
        audience: ClaimsAudience::IdToken,
        clientId: 'client-uuid',
        scopes: $scopes,
    ));
}

it('maps the profile and email scopes onto the user attributes', function (): void {
    $user = User::create(['name' => 'Manuel', 'email' => 'manuel@example.com', 'email_verified_at' => now(), 'password' => 'secret']);
    $user->forceFill(['locale' => 'de', 'timezone' => 'Europe/Berlin']);

    $profile = standardClaims($user, ['profile']);

    expect($profile)->toHaveKey('name', 'Manuel')
        ->and($profile)->toHaveKey('updated_at')
        ->and($profile)->toHaveKey('locale', 'de')
        ->and($profile)->toHaveKey('zoneinfo', 'Europe/Berlin')
        ->and(standardClaims($user, ['email']))->toBe(['email' => 'manuel@example.com', 'email_verified' => true])
        ->and(standardClaims($user, ['openid']))->toBe([]);
});

it('reports an unverified email and omits attributes the user does not carry', function (): void {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);

    expect(standardClaims($user, ['email']))->toBe(['email' => 'm@example.com', 'email_verified' => false])
        ->and(array_keys(standardClaims($user, ['profile'])))->not->toContain('locale', 'zoneinfo');
});

it('never reads a column a strict model does not carry', function (): void {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x'])->fresh();
    Model::preventAccessingMissingAttributes();

    try {
        expect(standardClaims($user, ['profile', 'email']))
            ->toHaveKeys(['name', 'email'])
            ->not->toHaveKey('locale');
    } finally {
        Model::preventAccessingMissingAttributes(false);
    }
});
