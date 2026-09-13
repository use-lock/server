<?php
declare(strict_types=1);

use Illuminate\Contracts\Auth\Authenticatable;
use Lattice\Facades\Effects;
use Lattice\Form\Components\Choice;
use Lattice\Form\Components\Form;
use Lattice\Ui\Effects\Builtin\OpenModal;
use Lock\Server\Credentials\FactorRegistry;
use Lock\Server\Credentials\RecoveryCodeProvider;
use Lock\Server\Credentials\TotpFactorProvider;
use Lock\Server\Credentials\Ui\Forms\TwoFactorSetupForm;
use Lock\Server\Shared\Credentials\EnrollableFactorProvider;
use Lock\Server\Shared\Credentials\EnrollmentOption;
use Lock\Server\Shared\Credentials\FactorChallenge;
use Lock\Server\Shared\Credentials\FactorEnrollment;
use Lock\Server\Shared\Credentials\FactorRole;
use Lock\Server\Shared\Credentials\FactorSetupKind;
use Lock\Server\Shared\Credentials\FactorVerification;
use PragmaRX\Google2FA\Google2FA;
use Workbench\App\Models\User;

final class FlashedEffectsRecorder
{
    /** @var list<object> */
    public array $effects = [];

    public function flash(object ...$effects): void
    {
        array_push($this->effects, ...$effects);
    }

    /**
     * @return list<string|null>
     */
    public function openedModalIds(): array
    {
        return array_map(
            static fn (OpenModal $effect): ?string => $effect->node->componentId(),
            array_values(array_filter($this->effects, static fn (object $effect): bool => $effect instanceof OpenModal)),
        );
    }
}

/**
 * Observes Lattice's own effect flasher instead of Inertia's flash bag, whose
 * internals vary across inertia-laravel versions.
 */
function recordFlashedEffects(): FlashedEffectsRecorder
{
    $recorder = new FlashedEffectsRecorder;
    Effects::swap($recorder);

    return $recorder;
}

function setupUser(): User
{
    return User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);
}

function pickerChoice(): Choice
{
    $choice = app(TwoFactorSetupForm::class)
        ->definition(Form::make('form'), request())
        ->fields()
        ->firstWhere(fn ($field): bool => $field->name() === 'option');

    assert($choice instanceof Choice);

    return $choice;
}

/**
 * @return array<string, mixed>
 */
function resolveSetupField(mixed $test, User $user, string $option): array
{
    return $test->actingAs($user)
        ->submitForm(TwoFactorSetupForm::class, ['_sub' => 'resolve', 'option' => $option])
        ->assertOk()
        ->json('fields.setup.props');
}

test('the picker offers every enrollment option with its role, recommended first and preselected', function (): void {
    $choice = pickerChoice();

    expect(array_column($choice->options, 'value'))->toBe(['passkey', 'security_key', 'totp'])
        ->and($choice->value)->toBe('passkey')
        ->and($choice->options[0]->data)->toMatchArray([
            'recommended' => true,
            'role' => __('oidc-ui::security.role.login-and-second-factor'),
            'icon' => 'fingerprint',
        ])
        ->and($choice->options[2]->data)->toMatchArray([
            'role' => __('oidc-ui::security.role.second-factor-only'),
            'description' => __('oidc-ui::security.option.totp.description'),
        ]);
});

test('resolving a code option begins the enrollment and returns its setup payload', function (): void {
    $user = setupUser();

    $props = resolveSetupField($this, $user, 'totp');

    expect($props['kind'])->toBe('code')
        ->and($props['secret'])->toBeString()
        ->and($props['qrSvg'])->toContain('<svg')
        ->and($user->totpFactors()->whereNull('confirmed_at')->count())->toBe(1)
        ->and($user->recoveryCodes()->count())->toBe(0);
});

test('resolving again for the same option reuses the pending enrollment', function (): void {
    $user = setupUser();

    $first = resolveSetupField($this, $user, 'totp');
    $second = resolveSetupField($this, $user, 'totp');

    expect($second['secret'])->toBe($first['secret'])
        ->and($user->totpFactors()->count())->toBe(1);
});

test('resolving a ceremony option asks the browser for the named authenticator', function (string $option, string $attachment): void {
    config(['passkeys.user_handle_secret' => 'user-handle-secret']);

    $props = resolveSetupField($this, setupUser(), $option);

    expect($props['kind'])->toBe('ceremony')
        ->and($props['enrollmentId'])->toBe('pending')
        ->and($props['webauthnOptions']['authenticatorSelection']['authenticatorAttachment'])->toBe($attachment);
})->with([
    ['passkey', 'platform'],
    ['security_key', 'cross-platform'],
]);

test('switching the ceremony option reissues the challenge', function (): void {
    config(['passkeys.user_handle_secret' => 'user-handle-secret']);
    $user = setupUser();

    $passkey = resolveSetupField($this, $user, 'passkey');
    $securityKey = resolveSetupField($this, $user, 'security_key');

    expect($securityKey['webauthnOptions']['challenge'])->not->toBe($passkey['webauthnOptions']['challenge']);
});

test('finishing the wizard confirms the factor and shows the fresh recovery codes', function (): void {
    $recorder = recordFlashedEffects();
    $user = setupUser();
    resolveSetupField($this, $user, 'totp');
    $factor = app(TotpFactorProvider::class)->latestPendingFactor($user);

    $this->actingAs($user)
        ->withHeader('X-Inertia', 'true')
        ->submitForm(TwoFactorSetupForm::class, [
            'option' => 'totp',
            'setup' => app(Google2FA::class)->getCurrentOtp($factor->secret),
        ])
        ->assertRedirect();

    expect($recorder->openedModalIds())->toBe(['oidc.recovery-codes'])
        ->and($user->totpFactors()->whereNotNull('confirmed_at')->exists())->toBeTrue()
        ->and($user->recoveryCodes()->count())->toBe(8);
});

test('a second factor is confirmed without reissuing recovery codes', function (): void {
    $user = setupUser();
    $first = app(TotpFactorProvider::class)->enroll($user);
    $first->forceFill(['confirmed_at' => now()])->save();
    app(RecoveryCodeProvider::class)->generate($user);
    $codes = app(RecoveryCodeProvider::class)->codes($user);

    resolveSetupField($this, $user, 'totp');
    $pending = app(TotpFactorProvider::class)->latestPendingFactor($user);

    $this->actingAs($user)
        ->withHeader('X-Inertia', 'true')
        ->submitForm(TwoFactorSetupForm::class, [
            'option' => 'totp',
            'setup' => app(Google2FA::class)->getCurrentOtp($pending->secret),
        ])
        ->assertRedirect();

    expect(app(RecoveryCodeProvider::class)->codes($user))
        ->toBe($codes);
});

test('a confirmation that does not prove the setup returns a field error', function (): void {
    $user = setupUser();
    resolveSetupField($this, $user, 'totp');

    $this->actingAs($user)
        ->submitForm(TwoFactorSetupForm::class, ['option' => 'totp', 'setup' => '000000'])
        ->assertInvalid(['setup']);

    expect($user->totpFactors()->whereNotNull('confirmed_at')->exists())->toBeFalse();
});

test('the host can point the wizard at its own recovery codes modal', function (): void {
    $recorder = recordFlashedEffects();
    $user = setupUser();
    $context = ['recovery_codes_modal' => 'host.custom-codes'];
    $this->actingAs($user)->submitForm(TwoFactorSetupForm::class, ['_sub' => 'resolve', 'option' => 'totp'], $context);
    $factor = app(TotpFactorProvider::class)->latestPendingFactor($user);

    $this->actingAs($user)->withHeader('X-Inertia', 'true')->submitForm(TwoFactorSetupForm::class, [
        'option' => 'totp',
        'setup' => app(Google2FA::class)->getCurrentOtp($factor->secret),
    ], $context)->assertRedirect();

    expect($recorder->openedModalIds())->toBe(['host.custom-codes']);
});

test('a ceremony credential submitted as a JSON string reaches the provider decoded', function (): void {
    $provider = new class implements EnrollableFactorProvider
    {
        /** @var array<string, mixed>|null */
        public ?array $confirmedWith = null;

        public function key(): string
        {
            return 'fake-ceremony';
        }

        public function isBackup(): bool
        {
            return false;
        }

        public function enrollmentOptions(): array
        {
            return [new EnrollmentOption('fake_ceremony', $this->key(), FactorRole::SecondFactorOnly, FactorSetupKind::Ceremony)];
        }

        public function enrollments(Authenticatable $user): array
        {
            return [new FactorEnrollment($this->key(), 'pending', 'Fake', null, null)];
        }

        public function beginEnrollment(Authenticatable $user, ?EnrollmentOption $option = null, ?string $name = null): FactorEnrollment
        {
            return $this->enrollments($user)[0];
        }

        public function confirmEnrollment(Authenticatable $user, FactorEnrollment $enrollment, array $input): bool
        {
            $this->confirmedWith = $input;

            return true;
        }

        public function revoke(Authenticatable $user, FactorEnrollment $enrollment): void {}

        public function beginChallenge(Authenticatable $user, FactorEnrollment $enrollment): FactorChallenge
        {
            return new FactorChallenge($enrollment);
        }

        public function verify(Authenticatable $user, FactorChallenge $challenge, array $input): FactorVerification
        {
            return new FactorVerification(false);
        }
    };
    app(FactorRegistry::class)->register($provider);
    $credential = ['id' => 'abc', 'response' => ['clientDataJSON' => 'payload']];

    $this->actingAs(setupUser())
        ->withHeader('X-Inertia', 'true')
        ->submitForm(TwoFactorSetupForm::class, [
            'option' => 'fake_ceremony',
            'setup' => [
                'credential' => (string) json_encode($credential),
                'name' => 'My key',
            ],
        ])
        ->assertRedirect();

    expect($provider->confirmedWith)->toBe(['credential' => $credential, 'name' => 'My key']);
});

test('an unknown enrollment option is rejected', function (): void {
    $this->actingAs(setupUser())
        ->submitForm(TwoFactorSetupForm::class, ['option' => 'sms', 'setup' => '000000'])
        ->assertInvalid(['option']);
});
