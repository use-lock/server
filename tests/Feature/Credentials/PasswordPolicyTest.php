<?php

declare(strict_types=1);

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\CanResetPassword;
use Illuminate\Support\Facades\Hash;
use Lock\Server\Credentials\Models\PasswordHistory;
use Lock\Server\Shared\Credentials\PasswordCredential;
use Workbench\App\Models\User;

function persistResetPasswords(): void
{
    resetUserPasswordsUsing(function (CanResetPassword $user, array $input): void {
        $user->forceFill(['password' => Hash::make($input['password'])])->save();
    });
}

/** @return array<string, string> */
function resetPasswordRequest(User $user, string $password): array
{
    return [
        'token' => passwordResetToken($user),
        'email' => 'm@example.com',
        'password' => $password,
        'password_confirmation' => $password,
    ];
}

/** A successful reset signs the user in, and the reset route is guest-only. */
function resetPasswordTo(mixed $test, User $user, string $password): void
{
    $test->postJson(route('identity.password.update'), resetPasswordRequest($user, $password))->assertOk();
    auth()->guard('identity')->logout();
}

function userWithPassword(string $password = 'old-password'): User
{
    return User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make($password)]);
}

it('rejects a reset password below the realm minimum length before the app action runs', function (): void {
    config(['oidc.password_policy.min_length' => 12]);
    $user = userWithPassword();
    $actionRan = false;

    resetUserPasswordsUsing(function () use (&$actionRan): void {
        $actionRan = true;
    });

    $this->postJson(route('identity.password.update'), resetPasswordRequest($user, 'short-pass'))
        ->assertStatus(422)
        ->assertJsonValidationErrors('password');

    expect($actionRan)->toBeFalse();
    $this->assertGuest('identity');
});

it('applies the composition rules of the realm policy', function (): void {
    config(['oidc.password_policy.mixed_case' => true, 'oidc.password_policy.numbers' => true, 'oidc.password_policy.symbols' => true]);
    $user = userWithPassword();
    persistResetPasswords();

    $this->postJson(route('identity.password.update'), resetPasswordRequest($user, 'lowercaseonly'))
        ->assertStatus(422)
        ->assertJsonValidationErrors('password');

    $this->postJson(route('identity.password.update'), resetPasswordRequest($user, 'Mixed-Case-1!'))
        ->assertOk();
});

it('refuses a password from the history window and records every change', function (): void {
    config(['oidc.password_policy.history' => 2]);
    $user = userWithPassword('first-password');
    persistResetPasswords();

    resetPasswordTo($this, $user, 'second-password');

    $this->postJson(route('identity.password.update'), resetPasswordRequest($user, 'second-password'))
        ->assertStatus(422)
        ->assertJsonValidationErrors('password');

    resetPasswordTo($this, $user, 'third-password');

    $this->postJson(route('identity.password.update'), resetPasswordRequest($user, 'second-password'))
        ->assertStatus(422)
        ->assertJsonValidationErrors('password');

    resetPasswordTo($this, $user, 'first-password');

    expect(PasswordHistory::query()->count())->toBe(2)
        ->and(Hash::check('first-password', (string) $user->fresh()?->getAuthPassword()))->toBeTrue();
});

it('keeps the current password out of reach even before the package has tracked it', function (): void {
    config(['oidc.password_policy.history' => 1]);
    $user = userWithPassword('current-password');
    persistResetPasswords();

    $this->postJson(route('identity.password.update'), resetPasswordRequest($user, 'current-password'))
        ->assertStatus(422)
        ->assertJsonValidationErrors('password');
});

it('validates a registration password against the realm policy before creating the user', function (): void {
    config(['oidc.password_policy.min_length' => 12]);

    createUsersUsing(fn (array $input): Authenticatable => User::create([
        'name' => $input['name'],
        'email' => $input['email'],
        'password' => Hash::make($input['password']),
    ]));

    $this->postJson(route('identity.register.store'), [
        'name' => 'M',
        'email' => 'm@example.com',
        'password' => 'short',
        'password_confirmation' => 'short',
    ])->assertStatus(422)->assertJsonValidationErrors('password');

    expect(User::query()->count())->toBe(0);

    $this->postJson(route('identity.register.store'), [
        'name' => 'M',
        'email' => 'm@example.com',
        'password' => 'long-enough-password',
        'password_confirmation' => 'long-enough-password',
    ])->assertCreated();

    expect(PasswordHistory::query()->count())->toBe(1);
});

it('starts tracking a password on the first login and reports rotation against max_age_days', function (): void {
    config(['oidc.password_policy.max_age_days' => 30]);
    $user = userWithPassword('password');
    $passwords = app(PasswordCredential::class);

    expect($passwords->changedAt($user))->toBeNull()
        ->and($passwords->isExpired($user))->toBeFalse();

    $this->postJson(route('identity.login.store'), ['email' => 'm@example.com', 'password' => 'password'])->assertOk();

    expect($passwords->changedAt($user))->not->toBeNull()
        ->and($passwords->isExpired($user))->toBeFalse();

    $this->travel(31)->days();

    expect($passwords->isExpired($user))->toBeTrue();

    $this->travelBack();
    auth()->guard('identity')->logout();
    $this->postJson(route('identity.login.store'), ['email' => 'm@example.com', 'password' => 'password'])->assertOk();

    expect(PasswordHistory::query()->count())->toBe(1);
});

it('does not expire a password when the realm sets no maximum age', function (): void {
    $user = userWithPassword('password');
    $passwords = app(PasswordCredential::class);

    $this->postJson(route('identity.login.store'), ['email' => 'm@example.com', 'password' => 'password'])->assertOk();
    $this->travel(400)->days();

    expect($passwords->isExpired($user))->toBeFalse();
});
