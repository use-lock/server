<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Laravel\Passkeys\Actions\VerifyPasskey;
use Laravel\Passkeys\Contracts\PasskeyUser;
use Laravel\Passkeys\Exceptions\InvalidPasskeyException;
use Laravel\Passkeys\Passkey;
use Lock\Server\Authentication\Ui\Views\TwoFactorChallengePrompt;
use Lock\Server\Authentication\Ui\Views\TwoFactorChallengeView;
use Lock\Server\Credentials\RecoveryCodeProvider;
use Lock\Server\Credentials\TotpFactorProvider;
use ParagonIE\ConstantTime\Base64UrlSafe;
use PragmaRX\Google2FA\Google2FA;
use Symfony\Component\HttpFoundation\Response;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialRequestOptions;
use Workbench\App\Models\User;

beforeEach(function (): void {
    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('password')]);
});

function challengeEnrollTotp(User $user): string
{
    $factor = app(TotpFactorProvider::class)->enroll($user);
    $factor->forceFill(['confirmed_at' => now()])->save();
    app(RecoveryCodeProvider::class)->generate($user);

    return $factor->secret;
}

function challengeEnrollPasskey(User $user): Passkey
{
    return $user->passkeys()->create([
        'name' => 'Key',
        'credential_id' => Base64UrlSafe::encodeUnpadded(random_bytes(16)),
        'credential' => ['type' => 'public-key'],
    ]);
}

function challengeVerifiesPasskey(?Passkey $passkey): void
{
    app()->instance(VerifyPasskey::class, new class($passkey) extends VerifyPasskey
    {
        public function __construct(private readonly ?Passkey $result) {}

        public function __invoke(
            PublicKeyCredential $credential,
            PublicKeyCredentialRequestOptions $options,
            ?PasskeyUser $user = null,
        ): Passkey {
            return $this->result ?? throw InvalidPasskeyException::make('Unable to verify passkey.');
        }
    });
}

/**
 * @return array<string, mixed>
 */
function challengeAssertionPayload(): array
{
    return [
        'id' => 'AQIDBA',
        'rawId' => 'AQIDBA',
        'type' => 'public-key',
        'authenticatorAttachment' => null,
        'response' => [
            'clientDataJSON' => Base64UrlSafe::encodeUnpadded((string) json_encode([
                'type' => 'webauthn.get', 'challenge' => 'AQIDBA', 'origin' => 'http://localhost',
            ])),
            'authenticatorData' => Base64UrlSafe::encodeUnpadded(str_repeat("\x00", 32)."\x01".pack('N', 1)),
            'signature' => 'AQIDBA',
            'userHandle' => null,
        ],
    ];
}

/**
 * @param  array<string, mixed>  $extra
 */
function pendingChallenge(mixed $test, User $user, string $factor = 'totp', array $extra = []): mixed
{
    return $test->withSession(['login.id' => $user->getAuthIdentifier(), 'login.factor' => $factor, ...$extra]);
}

it('rejects invalid and replayed TOTP codes', function (): void {
    $secret = challengeEnrollTotp($this->user);

    pendingChallenge($this, $this->user)
        ->post(route('identity.two-factor.login.store'), ['code' => '000000'])
        ->assertSessionHasErrors('code');

    $code = app(Google2FA::class)->getCurrentOtp($secret);

    pendingChallenge($this, $this->user)
        ->post(route('identity.two-factor.login.store'), ['code' => $code])
        ->assertRedirect('/dashboard');

    auth('identity')->logout();

    pendingChallenge($this, $this->user)
        ->post(route('identity.two-factor.login.store'), ['code' => $code])
        ->assertSessionHasErrors('code');
});

it('rejects a recovery code that was already used', function (): void {
    challengeEnrollTotp($this->user);
    $recoveryCode = $this->user->recoveryCodes()->firstOrFail()->code;

    pendingChallenge($this, $this->user)
        ->post(route('identity.two-factor.login.store'), ['recovery_code' => $recoveryCode])
        ->assertRedirect('/dashboard');

    auth('identity')->logout();

    pendingChallenge($this, $this->user)
        ->post(route('identity.two-factor.login.store'), ['recovery_code' => $recoveryCode])
        ->assertSessionHasErrors('recovery_code');
});

it('redirects challenge and factor-switch requests without a pending login to the login page', function (): void {
    $this->get(route('identity.two-factor.login'))->assertRedirect(route('identity.login'));
    $this->get(route('identity.two-factor.login.factor', ['provider' => 'totp']))->assertRedirect(route('identity.login'));
    $this->getJson(route('identity.two-factor.login.options'))->assertUnauthorized();
});

it('exposes the pending factor and the available factors on the challenge prompt', function (): void {
    app()->bind(TwoFactorChallengeView::class, fn (): TwoFactorChallengeView => new class implements TwoFactorChallengeView
    {
        public function respond(TwoFactorChallengePrompt $prompt, Request $request): Response
        {
            return response()->json($prompt);
        }
    });
    challengeEnrollTotp($this->user);
    challengeEnrollPasskey($this->user);

    pendingChallenge($this, $this->user)
        ->get(route('identity.two-factor.login'))
        ->assertOk()
        ->assertJson(['factor' => 'totp'])
        ->assertJsonPath('availableFactors.0.providerKey', 'totp')
        ->assertJsonPath('availableFactors.1.providerKey', 'webauthn');
});

it('switches the pending challenge to another enrolled factor and drops stale challenge state', function (): void {
    challengeEnrollTotp($this->user);
    $passkey = challengeEnrollPasskey($this->user);

    pendingChallenge($this, $this->user, extra: ['login.challenge_state' => ['options' => 'stale']])
        ->get(route('identity.two-factor.login.factor', ['provider' => 'webauthn']))
        ->assertRedirect(route('identity.two-factor.login'))
        ->assertSessionHas('login.factor', 'webauthn')
        ->assertSessionHas('login.factor_id', (string) $passkey->getKey())
        ->assertSessionMissing('login.challenge_state');
});

it('switches to a specific enrollment and keeps the current one for an unknown id', function (): void {
    $first = app(TotpFactorProvider::class)->enroll($this->user);
    $first->forceFill(['confirmed_at' => now()])->save();
    $second = app(TotpFactorProvider::class)->enroll($this->user, 'Second');
    $second->forceFill(['confirmed_at' => now()])->save();

    pendingChallenge($this, $this->user, extra: ['login.factor_id' => (string) $first->getKey()])
        ->get(route('identity.two-factor.login.factor', ['provider' => 'totp', 'enrollment' => (string) $second->getKey()]))
        ->assertRedirect(route('identity.two-factor.login'))
        ->assertSessionHas('login.factor_id', (string) $second->getKey());

    pendingChallenge($this, $this->user, extra: ['login.factor_id' => (string) $first->getKey()])
        ->get(route('identity.two-factor.login.factor', ['provider' => 'totp', 'enrollment' => 'unknown']))
        ->assertRedirect(route('identity.two-factor.login'))
        ->assertSessionHas('login.factor_id', (string) $first->getKey());
});

it('ignores a switch to a provider without a challengeable enrollment', function (string $provider): void {
    challengeEnrollTotp($this->user);

    pendingChallenge($this, $this->user)
        ->get(route('identity.two-factor.login.factor', ['provider' => $provider]))
        ->assertRedirect(route('identity.two-factor.login'))
        ->assertSessionHas('login.factor', 'totp');
})->with(['webauthn', 'recovery_code']);

it('issues WebAuthn options into private challenge state and rejects an assertion without them', function (): void {
    $passkey = challengeEnrollPasskey($this->user);
    challengeVerifiesPasskey($passkey);

    pendingChallenge($this, $this->user, 'webauthn', ['login.factor_id' => (string) $passkey->getKey()])
        ->post(route('identity.two-factor.login.store'), ['credential' => challengeAssertionPayload()])
        ->assertSessionHasErrors('code');

    $this->assertGuest('identity');

    pendingChallenge($this, $this->user, 'webauthn', ['login.factor_id' => (string) $passkey->getKey()])
        ->getJson(route('identity.two-factor.login.options'))
        ->assertOk()
        ->assertJsonStructure(['options']);

    expect(session('login.challenge_state'))->toBeArray()->toHaveKey('options');
});

it('accepts any of the user passkeys, not only the pinned enrollment', function (): void {
    $pinned = challengeEnrollPasskey($this->user);
    challengeVerifiesPasskey(challengeEnrollPasskey($this->user));

    pendingChallenge($this, $this->user, 'webauthn', ['login.factor_id' => (string) $pinned->getKey()])
        ->getJson(route('identity.two-factor.login.options'))
        ->assertOk();

    $this->post(route('identity.two-factor.login.store'), ['credential' => challengeAssertionPayload()])
        ->assertRedirect('/dashboard');

    $this->assertAuthenticatedAs($this->user, 'identity');
});

it('consumes the WebAuthn challenge state on a failed assertion', function (): void {
    $passkey = challengeEnrollPasskey($this->user);
    challengeVerifiesPasskey(null);

    pendingChallenge($this, $this->user, 'webauthn', ['login.factor_id' => (string) $passkey->getKey()])
        ->getJson(route('identity.two-factor.login.options'))
        ->assertOk();

    $this->post(route('identity.two-factor.login.store'), ['credential' => challengeAssertionPayload()])
        ->assertSessionHasErrors('code');

    expect(session('login.challenge_state'))->toBeNull();
    $this->assertGuest('identity');
});
