<?php
declare(strict_types=1);

use Illuminate\Auth\GenericUser;
use Illuminate\Auth\Notifications\VerifyEmail;
use Illuminate\Support\Facades\Notification;
use Lock\Server\Authentication\Ui\Actions\SendVerificationEmailAction;
use Lock\Server\Credentials\RecoveryCodeProvider;
use Lock\Server\Credentials\TotpFactorProvider;
use Lock\Server\Credentials\Ui\Actions\RegenerateRecoveryCodesAction;
use Lock\Server\Credentials\Ui\Actions\RevokeFactorAction;
use Lock\Server\Credentials\Ui\Fragments\RecoveryCodesFragment;
use Lock\Server\Credentials\Ui\Tables\TwoFactorMethodsTable;
use Workbench\App\Models\User;

test('the regenerate action replaces the recovery codes and opens them in a modal', function (): void {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);
    app(TotpFactorProvider::class)->enroll($user);
    $originalCodes = app(RecoveryCodeProvider::class)->generate($user);

    $response = $this->actingAs($user)
        ->callAction(RegenerateRecoveryCodesAction::class)
        ->assertSuccessful()
        ->assertOpensModal('oidc.recovery-codes');

    /** @var array<int, array<string, mixed>> $effects */
    $effects = $response->json('effects');
    $modal = collect($effects)->firstWhere('type', 'open-modal');

    expect($modal['props']['node']['schema'][0])
        ->toMatchArray(['type' => 'fragment', 'id' => 'oidc.recovery-codes'])
        ->and(app(RecoveryCodeProvider::class)->codes($user))
        ->toHaveCount(8)
        ->not->toBe($originalCodes);
});

test('the recovery codes fragment renders the unused codes', function (): void {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);
    $codes = app(RecoveryCodeProvider::class)->generate($user);

    $this->actingAs($user)
        ->loadFragment(RecoveryCodesFragment::class)
        ->assertOk()
        ->assertSee($codes[0])
        ->assertSee(__('oidc-ui::security.recovery-codes.description'), false);
});

test('the recovery codes fragment reports when no codes exist', function (): void {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);

    $this->actingAs($user)
        ->loadFragment(RecoveryCodesFragment::class)
        ->assertOk()
        ->assertSee(__('oidc-ui::security.recovery-codes.none'), false);
});

test('the methods table lists confirmed enrollments across providers with their role', function (): void {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);
    app(TotpFactorProvider::class)->enroll($user, 'Work phone');
    $user->totpFactors()->update(['confirmed_at' => now()]);
    app(TotpFactorProvider::class)->enroll($user, 'Pending phone');
    $user->passkeys()->create(['name' => 'Yubikey', 'credential_id' => 'credential-id', 'credential' => []]);

    /** @var array<int, array<string, mixed>> $data */
    $data = $this->actingAs($user)->loadTable(TwoFactorMethodsTable::class)->assertOk()->json('data');
    $rows = collect($data);

    expect($rows->pluck('label')->all())->toBe(['Work phone', 'Yubikey'])
        ->and($rows->firstWhere('label', 'Work phone'))->toMatchArray([
            'role' => __('oidc-ui::security.role.second-factor-only'),
            'description' => __('oidc-ui::auth.two-factor.method.totp'),
            'last_used_at_diff' => __('oidc-ui::security.methods.never-used'),
        ])
        ->and($rows->firstWhere('label', 'Yubikey'))->toMatchArray([
            'role' => __('oidc-ui::security.role.login-and-second-factor'),
            'description' => __('oidc-ui::auth.two-factor.method.webauthn'),
        ])
        ->and($rows->pluck('actions')->map(fn (array $actions): int => count($actions))->all())->toBe([1, 1]);
});

test('the methods table backs the list with a recovery-codes row', function (): void {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);
    app(TotpFactorProvider::class)->enroll($user, 'Work phone');
    $user->totpFactors()->update(['confirmed_at' => now()]);
    $codes = app(RecoveryCodeProvider::class);
    $codes->generate($user);
    $codes->verify($user, $codes->beginChallenge($user, $codes->enrollments($user)[0]), [
        'recovery_code' => $codes->codes($user)[0],
    ]);

    /** @var array<int, array<string, mixed>> $data */
    $data = $this->actingAs($user)->loadTable(TwoFactorMethodsTable::class)->assertOk()->json('data');
    $backup = collect($data)->firstWhere('label', __('oidc-ui::security.recovery-codes.heading'));

    expect($backup['description'])->toBe(__('oidc-ui::security.recovery-codes.remaining', ['remaining' => 7, 'total' => 8]))
        ->and($backup['role'])->toBe(__('oidc-ui::security.role.backup'))
        ->and($backup['actions'])->toHaveCount(1);
});

test('the methods table leaves the recovery-codes row out while nothing it backs up is confirmed', function (): void {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);
    app(TotpFactorProvider::class)->enroll($user, 'Pending phone');
    app(RecoveryCodeProvider::class)->generate($user);

    /** @var array<int, array<string, mixed>> $data */
    $data = $this->actingAs($user)->loadTable(TwoFactorMethodsTable::class)->assertOk()->json('data');

    expect($data)->toBe([]);
});

test('revoking the last challengeable factor takes the recovery codes with it', function (): void {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);
    $factor = app(TotpFactorProvider::class)->enroll($user);
    $factor->forceFill(['confirmed_at' => now()])->save();
    app(RecoveryCodeProvider::class)->generate($user);

    $this->actingAs($user)
        ->callAction(RevokeFactorAction::class, context: ['provider' => 'totp', 'enrollment' => (string) $factor->getKey()])
        ->assertSuccessful();

    expect($user->totpFactors()->exists())->toBeFalse()
        ->and($user->recoveryCodes()->exists())->toBeFalse();
});

test('revoking one of several factors keeps the recovery codes', function (): void {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);
    $factor = app(TotpFactorProvider::class)->enroll($user);
    $factor->forceFill(['confirmed_at' => now()])->save();
    $user->passkeys()->create(['name' => 'Yubikey', 'credential_id' => 'credential-id', 'credential' => []]);
    app(RecoveryCodeProvider::class)->generate($user);

    $this->actingAs($user)
        ->callAction(RevokeFactorAction::class, context: ['provider' => 'totp', 'enrollment' => (string) $factor->getKey()])
        ->assertSuccessful();

    expect($user->recoveryCodes()->count())->toBe(8)
        ->and($user->passkeys()->count())->toBe(1);
});

test('the revoke-factor action removes exactly the targeted enrollment', function (): void {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);
    $first = app(TotpFactorProvider::class)->enroll($user, 'First');
    $user->totpFactors()->update(['confirmed_at' => now()]);
    $second = app(TotpFactorProvider::class)->enroll($user, 'Second');
    $second->forceFill(['confirmed_at' => now()])->save();

    $this->actingAs($user)
        ->callAction(RevokeFactorAction::class, context: ['provider' => 'totp', 'enrollment' => (string) $first->getKey()])
        ->assertSuccessful();

    expect($user->totpFactors()->pluck('id')->all())->toBe([$second->getKey()]);
});

test('the revoke-factor action rejects foreign and unknown enrollments', function (): void {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);
    $other = User::create(['name' => 'O', 'email' => 'o@example.com', 'password' => 'secret']);
    $foreign = app(TotpFactorProvider::class)->enroll($other, 'Other');

    $this->actingAs($user)
        ->callDeniedAction(RevokeFactorAction::class, context: ['provider' => 'totp', 'enrollment' => (string) $foreign->getKey()])
        ->assertForbidden();

    $this->actingAs($user)
        ->callDeniedAction(RevokeFactorAction::class, context: ['provider' => 'webauthn', 'enrollment' => '1'])
        ->assertForbidden();

    expect($other->totpFactors()->exists())->toBeTrue();
});

test('the send-verification-email action notifies an unverified user', function (): void {
    Notification::fake();
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);

    $this->actingAs($user)
        ->callAction(SendVerificationEmailAction::class)
        ->assertSuccessful()
        ->assertJsonFragment([
            'type' => 'toast',
            'variant' => 'success',
            'message' => __('oidc-ui::security.verification-sent'),
        ]);

    Notification::assertSentTo($user, VerifyEmail::class);
});

test('the send-verification-email action reports an already-verified user without resending', function (): void {
    Notification::fake();
    $user = User::create([
        'name' => 'M',
        'email' => 'm@example.com',
        'password' => 'secret',
        'email_verified_at' => now(),
    ]);

    $this->actingAs($user)
        ->callAction(SendVerificationEmailAction::class)
        ->assertSuccessful()
        ->assertJsonFragment([
            'type' => 'toast',
            'variant' => 'info',
            'message' => __('oidc-ui::security.already-verified'),
        ]);

    Notification::assertNothingSent();
});

test('the send-verification-email action is forbidden for a user that cannot verify their email', function (): void {
    $user = new GenericUser(['id' => 1]);

    $this->actingAs($user)
        ->callAction(SendVerificationEmailAction::class)
        ->assertForbidden();
});
