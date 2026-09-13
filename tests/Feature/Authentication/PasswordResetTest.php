<?php

declare(strict_types=1);

use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Auth\Notifications\ResetPassword;
use Illuminate\Contracts\Auth\CanResetPassword;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Facades\Validator;
use Lock\Server\Authentication\Events\PasswordChanged;
use Lock\Server\Authentication\Models\PasswordResetToken;
use Workbench\App\Models\User;

it('sends a password reset link through the Laravel broker', function (): void {
    Notification::fake();

    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('old-password')]);

    $this->from('/auth/forgot-password')
        ->post(route('identity.password.email'), ['email' => 'm@example.com'])
        ->assertRedirect('/auth/forgot-password')
        ->assertSessionHas('status', __(Password::RESET_LINK_SENT));

    Notification::assertSentTo(
        $user,
        ResetPassword::class,
        fn (ResetPassword $notification): bool => str_contains(
            (string) $notification->toMail($user)->actionUrl,
            '/auth/reset-password/',
        ),
    );
});

it('resets a password through the package action seam and logs the user in', function (): void {
    Event::fake([PasswordReset::class, PasswordChanged::class]);

    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('old-password')]);
    $token = passwordResetToken($user);

    resetUserPasswordsUsing(function (CanResetPassword $user, array $input): void {
        $user->forceFill(['password' => Hash::make($input['password'])])->save();
    });

    DB::transaction(function () use ($token): void {
        $this->post(route('identity.password.update'), [
            'token' => $token,
            'email' => 'm@example.com',
            'password' => 'new-password',
            'password_confirmation' => 'new-password',
        ])->assertRedirect(route('identity.login'));
        Event::assertNotDispatched(PasswordReset::class);
    });

    $this->assertAuthenticatedAs($user->fresh(), 'identity');
    expect(session()->get('oidc.amr'))->toBe(['pwd']);
    expect(Hash::check('new-password', (string) User::query()->findOrFail($user->getKey())->getAttribute('password')))->toBeTrue()
        ->and(PasswordResetToken::query()->exists())->toBeFalse();
    Event::assertDispatched(PasswordReset::class);
    Event::assertNotDispatched(PasswordChanged::class);
});

it('refuses a reset link older than the realm lets it live', function (): void {
    config(['oidc.tokens.password_reset' => 600]);
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('old-password')]);
    $token = passwordResetToken($user);
    resetUserPasswordsUsing(function (CanResetPassword $user, array $input): void {
        $user->forceFill(['password' => Hash::make($input['password'])])->save();
    });

    $this->travel(11)->minutes();

    $this->postJson(route('identity.password.update'), [
        'token' => $token,
        'email' => 'm@example.com',
        'password' => 'new-password',
        'password_confirmation' => 'new-password',
    ])->assertJsonValidationErrors(['email' => __(Password::INVALID_TOKEN)]);
});

it('holds back a second reset link requested within a minute', function (): void {
    Notification::fake();
    User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('old-password')]);

    $this->postJson(route('identity.password.email'), ['email' => 'm@example.com'])->assertOk();
    $this->postJson(route('identity.password.email'), ['email' => 'm@example.com'])
        ->assertJsonValidationErrors(['email' => __(Password::RESET_THROTTLED)]);

    Notification::assertCount(1);
});

it('rejects a mismatched or missing password confirmation before reaching the reset action', function (): void {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('old-password')]);
    $token = passwordResetToken($user);
    $actionRan = false;

    resetUserPasswordsUsing(function (CanResetPassword $user, array $input) use (&$actionRan): void {
        $actionRan = true;

        $user->forceFill(['password' => Hash::make($input['password'])])->save();
    });

    $this->from('/auth/reset-password/'.$token)
        ->post(route('identity.password.update'), [
            'token' => $token,
            'email' => 'm@example.com',
            'password' => 'new-password',
            'password_confirmation' => 'a-different-password',
        ])
        ->assertRedirect('/auth/reset-password/'.$token)
        ->assertSessionHasErrors('password');

    $this->postJson(route('identity.password.update'), [
        'token' => $token,
        'email' => 'm@example.com',
        'password' => 'new-password',
    ])->assertStatus(422)->assertJsonValidationErrors('password');

    $this->assertGuest('identity');
    expect($actionRan)->toBeFalse()
        ->and(Hash::check('old-password', (string) User::query()->findOrFail($user->getKey())->getAttribute('password')))->toBeTrue();
});

it('rolls back a password write and retains the reset token when the host action rejects it', function (): void {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('old-password')]);
    $token = passwordResetToken($user);

    resetUserPasswordsUsing(function (CanResetPassword $user, array $input): void {
        $user->forceFill(['password' => Hash::make($input['password'])])->save();

        Validator::make($input, ['password' => ['min:20']])->validate();
    });

    $this->from('/auth/reset-password/'.$token)
        ->post(route('identity.password.update'), [
            'token' => $token,
            'email' => 'm@example.com',
            'password' => 'too-short',
            'password_confirmation' => 'too-short',
        ])
        ->assertRedirect('/auth/reset-password/'.$token)
        ->assertSessionHasErrors('password');

    $this->assertGuest('identity');
    expect(Hash::check('old-password', (string) User::query()->findOrFail($user->getKey())->getAttribute('password')))->toBeTrue()
        ->and(PasswordResetToken::query()->exists())->toBeTrue();
});

it('returns validation errors for an invalid reset token', function (): void {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('old-password')]);

    resetUserPasswordsUsing(function (CanResetPassword $user, array $input): void {
        $user->forceFill(['password' => Hash::make($input['password'])])->save();
    });

    $this->from('/auth/reset-password/invalid-token')
        ->post(route('identity.password.update'), [
            'token' => 'invalid-token',
            'email' => (string) $user->getAttribute('email'),
            'password' => 'new-password',
            'password_confirmation' => 'new-password',
        ])
        ->assertRedirect('/auth/reset-password/invalid-token')
        ->assertSessionHasErrors('email');

    $this->assertGuest('identity');
    expect(Hash::check('old-password', (string) User::query()->findOrFail($user->getKey())->getAttribute('password')))->toBeTrue();
});
