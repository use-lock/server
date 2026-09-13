<?php

declare(strict_types=1);

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\CanResetPassword;
use Illuminate\Support\Facades\Hash;
use Illuminate\Testing\TestResponse;
use Laravel\Passkeys\Actions\VerifyPasskey;
use Laravel\Passkeys\Contracts\PasskeyUser;
use Laravel\Passkeys\Passkey;
use Lock\Server\Authentication\Context\LoginState;
use Lock\Server\Authentication\Pipeline\LoginApi;
use Lock\Server\Authentication\Pipeline\LoginEvent;
use Lock\Server\Authentication\Pipeline\PostLoginPipeline;
use Lock\Server\Credentials\TotpFactorProvider;
use ParagonIE\ConstantTime\Base64UrlSafe;
use Symfony\Component\HttpFoundation\Response;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialRequestOptions;
use Workbench\App\Models\User;

function finalizationRegisterUsers(): void
{
    createUsersUsing(fn (array $input): Authenticatable => User::create([
        'name' => $input['name'],
        'email' => $input['email'],
        'password' => Hash::make($input['password']),
    ]));
}

/**
 * @return TestResponse<Response>
 */
function finalizationPasskeyLogin(mixed $test, User $user): TestResponse
{
    $passkey = $user->passkeys()->create([
        'name' => 'Key',
        'credential_id' => 'cred-'.uniqid(),
        'credential' => ['type' => 'public-key'],
    ]);

    app()->instance(VerifyPasskey::class, new class($passkey) extends VerifyPasskey
    {
        public function __construct(private readonly Passkey $result) {}

        public function __invoke(
            PublicKeyCredential $credential,
            PublicKeyCredentialRequestOptions $options,
            ?PasskeyUser $user = null,
        ): Passkey {
            return $this->result;
        }
    });

    $authenticatorData = Base64UrlSafe::encodeUnpadded(str_repeat("\x00", 32)."\x01".pack('N', 1));
    $clientDataJson = Base64UrlSafe::encodeUnpadded((string) json_encode([
        'type' => 'webauthn.get', 'challenge' => 'AQIDBA', 'origin' => 'http://localhost',
    ]));

    return $test->withSession([
        'passkey.verification_options' => (string) json_encode(['challenge' => 'AQIDBA', 'rpId' => 'localhost', 'timeout' => 60000]),
    ])->post(route('identity.passkey.login'), [
        'credential' => [
            'id' => 'AQIDBA',
            'rawId' => 'AQIDBA',
            'type' => 'public-key',
            'authenticatorAttachment' => null,
            'response' => [
                'clientDataJSON' => $clientDataJson,
                'authenticatorData' => $authenticatorData,
                'signature' => 'AQIDBA',
                'userHandle' => null,
            ],
        ],
    ]);
}

it('applies the postLogin policy to registration', function (): void {
    finalizationRegisterUsers();
    app(PostLoginPipeline::class)->register(fn (LoginEvent $e, LoginApi $api) => $api->deny('blocked'));

    $this->post(route('identity.register.store'), [
        'name' => 'M',
        'email' => 'm@example.com',
        'password' => 'password',
        'password_confirmation' => 'password',
    ]);

    expect(User::where('email', 'm@example.com')->exists())->toBeTrue();
    $this->assertGuest('identity');
});

it('applies the postLogin policy to password resets', function (): void {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('old-password')]);
    $token = passwordResetToken($user);

    resetUserPasswordsUsing(function (CanResetPassword $user, array $input): void {
        $user->forceFill(['password' => Hash::make($input['password'])])->save();
    });
    app(PostLoginPipeline::class)->register(fn (LoginEvent $e, LoginApi $api) => $api->deny('blocked'));

    $this->post(route('identity.password.update'), [
        'token' => $token,
        'email' => 'm@example.com',
        'password' => 'new-password',
        'password_confirmation' => 'new-password',
    ]);

    expect(Hash::check('new-password', (string) $user->fresh()->getAttribute('password')))->toBeTrue();
    $this->assertGuest('identity');
});

it('applies the postLogin policy to passkey logins', function (): void {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('password')]);
    app(PostLoginPipeline::class)->register(fn (LoginEvent $e, LoginApi $api) => $api->deny('blocked'));

    finalizationPasskeyLogin($this, $user)->assertSessionHasErrors();

    $this->assertGuest('identity');
});

it('does not challenge an enrolled second factor after a passkey login', function (): void {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('password')]);
    $factor = app(TotpFactorProvider::class)->enroll($user);
    $factor->forceFill(['confirmed_at' => now()])->save();

    finalizationPasskeyLogin($this, $user);

    $this->assertAuthenticatedAs($user, 'identity');
    expect(session(LoginState::AMR_KEY))->toContain('swk');
});

it('still requires a challenge after passkey login when the pipeline demands MFA', function (): void {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('password')]);
    $factor = app(TotpFactorProvider::class)->enroll($user);
    $factor->forceFill(['confirmed_at' => now()])->save();

    app(PostLoginPipeline::class)->register(fn (LoginEvent $e, LoginApi $api) => $api->requireMfa());

    finalizationPasskeyLogin($this, $user)->assertRedirect(route('identity.two-factor.login'));

    $this->assertGuest('identity');
});
