<?php

declare(strict_types=1);

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\CanResetPassword;
use Illuminate\Support\Facades\Hash;
use Lock\Server\Authentication\Pipeline\LoginApi;
use Lock\Server\Authentication\Pipeline\LoginEvent;
use Lock\Server\Authentication\Pipeline\PostLoginPipeline;
use Lock\Server\Credentials\RecoveryCodeProvider;
use Lock\Server\Credentials\TotpFactorProvider;
use Lock\Server\Shared\Audit\AuditEventType;
use Lock\Server\Shared\Audit\AuditRecord;
use PragmaRX\Google2FA\Google2FA;
use Workbench\App\Models\User;

function auditTestUser(): User
{
    return User::create(['name' => 'M', 'email' => 'audit@example.com', 'password' => Hash::make('password')]);
}

it('audits a successful password login with sid and amr', function (): void {
    $sink = fakeAudit();
    $user = auditTestUser();

    $this->post(route('identity.login.store'), ['email' => 'audit@example.com', 'password' => 'password']);

    $record = $sink->assertRecorded(AuditEventType::LoginSucceeded);

    expect($record->userId)->toBe((string) $user->getAuthIdentifier())
        ->and($record->sid)->not->toBeNull()
        ->and($record->context['amr'])->toBe(['pwd'])
        ->and($record->ip)->not->toBeNull();
});

it('audits a login attempt with invalid credentials', function (): void {
    $sink = fakeAudit();
    auditTestUser();

    $this->post(route('identity.login.store'), ['email' => 'audit@example.com', 'password' => 'wrong']);

    $sink->assertRecorded(AuditEventType::LoginFailed, fn (AuditRecord $record): bool => $record->context['reason'] === 'invalid_credentials'
        && $record->context['username'] === 'audit@example.com'
        && $record->context['method'] === 'pwd');
    $sink->assertNotRecorded(AuditEventType::LoginSucceeded);
});

it('audits a login denied by the postLogin policy', function (): void {
    $sink = fakeAudit();
    auditTestUser();
    app(PostLoginPipeline::class)->register(fn (LoginEvent $event, LoginApi $api) => $api->deny('blocked'));

    $this->post(route('identity.login.store'), ['email' => 'audit@example.com', 'password' => 'password']);

    $sink->assertRecorded(AuditEventType::LoginFailed, fn (AuditRecord $record): bool => $record->context['reason'] === 'policy_denied'
        && $record->context['deny_reason'] === 'blocked');
    $sink->assertNotRecorded(AuditEventType::LoginSucceeded);
});

it('audits a full mfa challenge round trip', function (): void {
    $sink = fakeAudit();
    $user = auditTestUser();
    $factor = app(TotpFactorProvider::class)->enroll($user);
    $factor->forceFill(['confirmed_at' => now()])->save();

    $this->post(route('identity.login.store'), ['email' => 'audit@example.com', 'password' => 'password'])
        ->assertRedirect(route('identity.two-factor.login'));

    $sink->assertNotRecorded(AuditEventType::LoginSucceeded);

    $this->post(route('identity.two-factor.login.store'), ['code' => '000000'])
        ->assertSessionHasErrors('code');

    $sink->assertRecorded(AuditEventType::MfaChallengeFailed, fn (AuditRecord $record): bool => $record->context['factor'] === 'totp'
        && $record->context['reason'] === 'invalid_code'
        && $record->userId === (string) $user->getAuthIdentifier());

    $code = app(Google2FA::class)->getCurrentOtp($factor->secret);

    $this->post(route('identity.two-factor.login.store'), ['code' => $code])
        ->assertRedirect('/dashboard');

    $sink->assertRecorded(AuditEventType::MfaChallengeSucceeded, fn (AuditRecord $record): bool => $record->context['factor'] === 'totp');
    $sink->assertRecorded(AuditEventType::LoginSucceeded, fn (AuditRecord $record): bool => $record->context['amr'] === ['pwd', 'otp']);
    $sink->assertNotRecorded(AuditEventType::RecoveryCodeUsed);
});

it('audits a recovery code login', function (): void {
    $sink = fakeAudit();
    $user = auditTestUser();
    $factor = app(TotpFactorProvider::class)->enroll($user);
    $factor->forceFill(['confirmed_at' => now()])->save();
    app(RecoveryCodeProvider::class)->generate($user);
    $recoveryCode = $user->recoveryCodes()->firstOrFail()->code;

    $this->withSession(['login.id' => $user->getAuthIdentifier(), 'login.factor' => 'totp'])
        ->post(route('identity.two-factor.login.store'), ['recovery_code' => $recoveryCode])
        ->assertRedirect('/dashboard');

    $sink->assertRecorded(AuditEventType::RecoveryCodeUsed, fn (AuditRecord $record): bool => $record->userId === (string) $user->getAuthIdentifier());
    $sink->assertRecorded(AuditEventType::MfaChallengeSucceeded, fn (AuditRecord $record): bool => $record->context['factor'] === 'recovery_code');
});

it('audits the factor enrollment lifecycle', function (): void {
    $sink = fakeAudit();
    $user = auditTestUser();
    $session = ['auth.password_confirmed_at' => time()];

    $enrollment = $this->actingAs($user, 'identity')->withSession($session)
        ->postJson(route('identity.two-factor.enroll', ['provider' => 'totp']))
        ->json();

    $sink->assertRecorded(AuditEventType::FactorEnrollmentStarted, fn (AuditRecord $record): bool => $record->context['factor'] === 'totp'
        && $record->context['enrollment_id'] === $enrollment['id']);

    $code = app(Google2FA::class)->getCurrentOtp($enrollment['metadata']['secret']);

    $this->actingAs($user, 'identity')->withSession($session)
        ->postJson(route('identity.two-factor.enroll.confirm', ['provider' => 'totp']), [
            'enrollment_id' => $enrollment['id'],
            'code' => $code,
        ])->assertOk();

    $sink->assertRecorded(AuditEventType::FactorConfirmed, fn (AuditRecord $record): bool => $record->context['factor'] === 'totp');

    $this->actingAs($user, 'identity')->withSession($session)
        ->deleteJson(route('identity.two-factor.revoke', ['provider' => 'totp', 'enrollment' => $enrollment['id']]))
        ->assertNoContent();

    $sink->assertRecorded(AuditEventType::FactorRevoked, fn (AuditRecord $record): bool => $record->context['factor'] === 'totp'
        && $record->context['enrollment_id'] === $enrollment['id']);
});

it('audits a registration', function (): void {
    $sink = fakeAudit();
    createUsersUsing(fn (array $input): Authenticatable => User::create([
        'name' => $input['name'],
        'email' => $input['email'],
        'password' => Hash::make($input['password']),
    ]));

    $this->post(route('identity.register.store'), [
        'name' => 'M',
        'email' => 'audit@example.com',
        'password' => 'password',
        'password_confirmation' => 'password',
    ])->assertRedirect('/dashboard');

    $user = User::where('email', 'audit@example.com')->firstOrFail();

    $sink->assertRecorded(AuditEventType::UserRegistered, fn (AuditRecord $record): bool => $record->userId === (string) $user->getAuthIdentifier());
    $sink->assertRecorded(AuditEventType::LoginSucceeded);
});

it('audits a password reset', function (): void {
    $sink = fakeAudit();
    $user = auditTestUser();
    $token = passwordResetToken($user);
    resetUserPasswordsUsing(function (CanResetPassword $user, array $input): void {
        $user->forceFill(['password' => Hash::make($input['password'])])->save();
    });

    $this->post(route('identity.password.update'), [
        'token' => $token,
        'email' => 'audit@example.com',
        'password' => 'new-password',
        'password_confirmation' => 'new-password',
    ]);

    $sink->assertRecorded(AuditEventType::PasswordReset, fn (AuditRecord $record): bool => $record->userId === (string) $user->getAuthIdentifier());
});

it('audits a logout with the sid still attached', function (): void {
    $sink = fakeAudit();
    $user = auditTestUser();

    $this->post(route('identity.login.store'), ['email' => 'audit@example.com', 'password' => 'password']);

    $this->post(route('oidc.logout'));

    $record = $sink->assertRecorded(AuditEventType::LoggedOut);

    expect($record->userId)->toBe((string) $user->getAuthIdentifier())
        ->and($record->sid)->not->toBeNull();
});
