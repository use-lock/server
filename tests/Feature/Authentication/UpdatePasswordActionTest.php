<?php

declare(strict_types=1);

use Illuminate\Contracts\Auth\CanResetPassword;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Lock\Server\Authentication\Contracts\ResetUserPassword;
use Lock\Server\Authentication\Events\PasswordChanged;
use Lock\Server\Authentication\RequiredActions\PendingRequiredActions;
use Lock\Server\Credentials\Models\PasswordHistory;
use Lock\Server\Support\Testing\FakesAuthViews;
use Workbench\App\Models\User;

uses(FakesAuthViews::class);

beforeEach(function (): void {
    $this->fakeAuthViews();
    config(['oidc.password_policy.max_age_days' => 30]);

    resetUserPasswordsUsing(function (CanResetPassword $user, array $input): void {
        $user->forceFill(['password' => Hash::make($input['password'])]);
    });
});

function userWithPasswordChangedAt(string $ago): User
{
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('password')]);

    $user->hasMany(PasswordHistory::class, 'user_id')
        ->create(['hash' => $user->getAuthPassword(), 'created_at' => now()->sub($ago)]);

    return $user;
}

it('holds the login on the change-password screen once the password expires', function (): void {
    userWithPasswordChangedAt('60 days');

    $this->post(route('identity.login.store'), ['email' => 'm@example.com', 'password' => 'password'])
        ->assertRedirect(route('identity.password.change'));

    $this->assertGuest('identity');
});

it('lets a password inside the rotation window through', function (): void {
    $user = userWithPasswordChangedAt('5 days');

    $this->post(route('identity.login.store'), ['email' => 'm@example.com', 'password' => 'password'])
        ->assertRedirect(config('oidc.login.home'));

    $this->assertAuthenticatedAs($user, 'identity');
});

it('does not ask for the current password mid-login', function (): void {
    userWithPasswordChangedAt('60 days');
    $this->post(route('identity.login.store'), ['email' => 'm@example.com', 'password' => 'password']);

    $this->get(route('identity.password.change'))
        ->assertOk()
        ->assertJsonPath('prompt.requiresCurrentPassword', false)
        ->assertJsonPath('prompt.expired', true);
});

it('completes the login once a fresh password is set', function (): void {
    Event::fake([PasswordChanged::class]);
    $user = userWithPasswordChangedAt('60 days');
    $this->post(route('identity.login.store'), ['email' => 'm@example.com', 'password' => 'password']);

    $this->post(route('identity.password.change.store'), [
        'password' => 'a-brand-new-password',
        'password_confirmation' => 'a-brand-new-password',
    ])->assertRedirect(config('oidc.login.home'));

    $this->assertAuthenticatedAs($user->fresh(), 'identity');
    expect(Hash::check('a-brand-new-password', $user->fresh()->getAuthPassword()))->toBeTrue()
        ->and(PendingRequiredActions::find())->toBeNull();
    Event::assertDispatched(PasswordChanged::class);
});

it('applies the realm password policy to the new password', function (): void {
    config(['oidc.password_policy.min_length' => 12]);
    userWithPasswordChangedAt('60 days');
    $this->post(route('identity.login.store'), ['email' => 'm@example.com', 'password' => 'password']);

    $this->post(route('identity.password.change.store'), ['password' => 'short', 'password_confirmation' => 'short'])
        ->assertSessionHasErrors('password');

    $this->assertGuest('identity');
});

it('refuses to reuse a password the history still remembers', function (): void {
    config(['oidc.password_policy.history' => 2]);
    userWithPasswordChangedAt('60 days');
    $this->post(route('identity.login.store'), ['email' => 'm@example.com', 'password' => 'password']);

    $this->post(route('identity.password.change.store'), ['password' => 'password', 'password_confirmation' => 'password'])
        ->assertSessionHasErrors('password');
});

it('asks a live session for the current password', function (): void {
    config(['oidc.password_policy.max_age_days' => null]);
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('password')]);
    $this->actingAs($user, 'identity');

    $this->get(route('identity.password.change'))
        ->assertOk()
        ->assertJsonPath('prompt.requiresCurrentPassword', true);

    $this->post(route('identity.password.change.store'), [
        'password' => 'a-brand-new-password',
        'password_confirmation' => 'a-brand-new-password',
    ])->assertSessionHasErrors('current_password');

    $this->post(route('identity.password.change.store'), [
        'current_password' => 'password',
        'password' => 'a-brand-new-password',
        'password_confirmation' => 'a-brand-new-password',
    ])->assertRedirect();

    expect(Hash::check('a-brand-new-password', $user->fresh()->getAuthPassword()))->toBeTrue();
});

it('closes the screen without a bound ResetUserPassword action', function (): void {
    config(['oidc.password_policy.max_age_days' => null]);
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('password')]);
    unset(app()[ResetUserPassword::class]);
    $this->actingAs($user, 'identity');

    $this->post(route('identity.password.change.store'), [
        'current_password' => 'password',
        'password' => 'a-brand-new-password',
        'password_confirmation' => 'a-brand-new-password',
    ])->assertNotFound();
});
