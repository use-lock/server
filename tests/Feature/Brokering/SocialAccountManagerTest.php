<?php

declare(strict_types=1);

use Illuminate\Auth\SessionGuard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Lock\Server\Brokering\Models\SocialAccount;
use Lock\Server\Brokering\SocialAccountManager;
use Lock\Server\Shared\Brokering\SocialUser;
use Workbench\App\Models\User;

/**
 * @param  array<string, mixed>  $overrides
 */
function socialUser(array $overrides = []): SocialUser
{
    return new SocialUser(...array_merge([
        'id' => 'g-123',
        'email' => 'm@example.com',
        'emailVerified' => true,
        'name' => 'M',
        'nickname' => null,
        'avatar' => null,
        'raw' => ['sub' => 'g-123'],
        'accessToken' => 'at-1',
        'refreshToken' => 'rt-1',
        'expiresIn' => 3600,
    ], $overrides));
}

function userProvider(): UserProvider
{
    $guard = Auth::guard('identity');

    if (! $guard instanceof SessionGuard) {
        throw new RuntimeException('Expected the identity guard to be a session guard.');
    }

    return $guard->getProvider();
}

it('resolves an already linked account, refreshes its tokens and keeps them encrypted at rest', function (): void {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);
    $manager = app(SocialAccountManager::class);
    $manager->link($user, 'google', socialUser(['accessToken' => 'old-at']));

    $resolved = $manager->resolveUser('google', socialUser(['accessToken' => 'new-at']), userProvider());
    $stored = DB::table('oidc_social_accounts')->sole();

    expect($resolved?->is($user))->toBeTrue()
        ->and(SocialAccount::query()->count())->toBe(1)
        ->and(SocialAccount::query()->sole()->access_token)->toBe('new-at')
        ->and($stored->access_token)->not->toContain('new-at')
        ->and($stored->refresh_token)->not->toContain('rt-1');
});

it('links by verified email only while enabled', function (): void {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);
    $manager = app(SocialAccountManager::class);

    expect($manager->resolveUser('google', socialUser(['emailVerified' => false]), userProvider()))->toBeNull();

    config()->set('oidc.social.link_by_verified_email', false);

    expect($manager->resolveUser('google', socialUser(), userProvider()))->toBeNull();

    config()->set('oidc.social.link_by_verified_email', true);

    expect($manager->resolveUser('google', socialUser(), userProvider())?->is($user))->toBeTrue()
        ->and(SocialAccount::query()->where('provider', 'google')->where('provider_user_id', 'g-123')->exists())->toBeTrue();
});

it('provisions a new user through the registered action only while auto-provisioning is enabled', function (): void {
    $manager = app(SocialAccountManager::class);

    expect($manager->resolveUser('google', socialUser(), userProvider()))->toBeNull();

    createUsersFromSocialUsing(fn (SocialUser $socialUser, string $provider): User => User::create([
        'name' => $socialUser->name ?? 'Unknown',
        'email' => $socialUser->email,
        'password' => Str::random(40),
    ]));

    config()->set('oidc.social.auto_provision', false);

    expect($manager->resolveUser('google', socialUser(), userProvider()))->toBeNull();

    config()->set('oidc.social.auto_provision', true);

    expect($manager->resolveUser('google', socialUser(), userProvider()))->toBeInstanceOf(User::class)
        ->and(SocialAccount::query()->count())->toBe(1);

    $this->assertDatabaseHas('users', ['email' => 'm@example.com']);

    SocialAccount::creating(function (SocialAccount $account): void {
        if ($account->provider === 'broken') {
            throw new RuntimeException('link unavailable');
        }
    });

    expect(fn () => $manager->resolveUser('broken', socialUser(['id' => 'broken-id', 'email' => 'broken@example.com']), userProvider()))
        ->toThrow(RuntimeException::class, 'link unavailable');

    $this->assertDatabaseMissing('users', ['email' => 'broken@example.com']);
    expect(SocialAccount::query()->count())->toBe(1);

});

it('preserves profile fields and the refresh token when a re-login omits them', function (): void {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);
    $manager = app(SocialAccountManager::class);
    $manager->link($user, 'apple', socialUser([
        'name' => 'M',
        'nickname' => 'em',
        'avatar' => 'https://cdn.example.com/m.png',
        'refreshToken' => 'rt-1',
    ]));

    $manager->resolveUser('apple', socialUser([
        'name' => null,
        'nickname' => null,
        'avatar' => null,
        'refreshToken' => null,
        'accessToken' => 'at-2',
    ]), userProvider());

    $account = SocialAccount::query()->sole();

    expect($account->name)->toBe('M')
        ->and($account->nickname)->toBe('em')
        ->and($account->avatar)->toBe('https://cdn.example.com/m.png')
        ->and($account->refresh_token)->toBe('rt-1')
        ->and($account->access_token)->toBe('at-2');
});

it('re-associates an existing link instead of duplicating it', function (): void {
    $userA = User::create(['name' => 'A', 'email' => 'a@example.com', 'password' => 'secret']);
    $userB = User::create(['name' => 'B', 'email' => 'b@example.com', 'password' => 'secret']);
    $manager = app(SocialAccountManager::class);

    $manager->link($userA, 'corp', socialUser(['id' => 'upstream-1']));
    $manager->link($userB, 'corp', socialUser(['id' => 'upstream-1']));

    expect(SocialAccount::query()->count())->toBe(1)
        ->and(SocialAccount::query()->sole()->user_id)->toBe((string) $userB->id);
});
