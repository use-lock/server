<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Hash;
use Lock\Server\Shared\Realms\RealmResolver;
use Lock\Server\Shared\Realms\Settings\AuthenticationSettings;
use Lock\Server\Shared\Realms\Settings\LoginMethod;
use Lock\Server\Shared\Realms\Settings\MfaRequirement;
use Lock\Server\Support\Testing\FakesAuthViews;
use Workbench\App\Models\User;

uses(FakesAuthViews::class);

it('reads the realm authentication settings from config', function (): void {
    config([
        'oidc.authentication.methods' => ['passkey', 'nonsense'],
        'oidc.authentication.mfa' => 'always',
        'oidc.authentication.email_verification_required' => true,
    ]);

    $settings = app(RealmResolver::class)->current()->authentication();

    expect($settings->methods)->toBe([LoginMethod::Passkey])
        ->and($settings->mfa)->toBe(MfaRequirement::Always)
        ->and($settings->emailVerificationRequired)->toBeTrue()
        ->and($settings->allows(LoginMethod::Password))->toBeFalse();
});

it('falls back to challenging enrolled factors for an unknown mfa setting', function (): void {
    config(['oidc.authentication.mfa' => 'sometimes']);

    expect(AuthenticationSettings::fromConfig()->mfa)->toBe(MfaRequirement::IfEnrolled);
});

it('refuses a password login in a realm that does not accept passwords', function (): void {
    config(['oidc.authentication.methods' => ['passkey']]);
    User::create(['name' => 'M', 'email' => 'user@example.com', 'password' => Hash::make('password')]);

    $this->post(route('identity.login.store'), ['email' => 'user@example.com', 'password' => 'password'])
        ->assertNotFound();

    $this->assertGuest('identity');
});

it('closes registration and password reset with the password method', function (): void {
    config(['oidc.authentication.methods' => ['passkey']]);

    $this->get(route('identity.register'))->assertNotFound();
    $this->get(route('identity.password.request'))->assertNotFound();
    $this->post(route('identity.password.email'), ['email' => 'user@example.com'])->assertNotFound();
});

it('closes the passkey and social routes the realm leaves out', function (): void {
    config(['oidc.authentication.methods' => ['password']]);

    $this->get(route('identity.passkey.login-options'))->assertNotFound();
    $this->get(route('identity.social.redirect', ['provider' => 'github']))->assertNotFound();
});

it('keeps the login page open so the remaining methods stay reachable', function (): void {
    config(['oidc.authentication.methods' => ['passkey']]);
    $this->fakeAuthViews();

    $this->get(route('identity.login'))
        ->assertOk()
        ->assertJsonPath('prompt.methods', ['passkey']);
});
