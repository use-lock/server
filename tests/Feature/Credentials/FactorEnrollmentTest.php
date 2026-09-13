<?php

declare(strict_types=1);

use CBOR\ByteStringObject;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\TextStringObject;
use CBOR\UnsignedIntegerObject;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Laravel\Passkeys\Actions\StorePasskey;
use Laravel\Passkeys\Passkey;
use Lock\Server\Credentials\Models\TotpFactor;
use Lock\Server\Shared\Audit\AuditEventType;
use ParagonIE\ConstantTime\Base64UrlSafe;
use PragmaRX\Google2FA\Google2FA;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Workbench\App\Models\User;

beforeEach(function (): void {
    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('password')]);
});

function enrolling(mixed $test): mixed
{
    return $test->actingAs($test->user, 'identity')->withSession(['auth.password_confirmed_at' => time()]);
}

function enrollConfirmedTotp(mixed $test): string
{
    $enrollment = enrolling($test)->postJson(route('identity.two-factor.enroll', ['provider' => 'totp']))->assertCreated()->json();

    enrolling($test)
        ->postJson(route('identity.two-factor.enroll.confirm', ['provider' => 'totp']), [
            'enrollment_id' => $enrollment['id'],
            'code' => app(Google2FA::class)->getCurrentOtp($enrollment['metadata']['secret']),
        ])->assertOk();

    return $enrollment['id'];
}

/**
 * A structurally valid "none"-format attestation credential: enough to pass
 * WebAuthn deserialization so the (stubbed) StorePasskey handoff is reached.
 *
 * @return array<string, mixed>
 */
function webauthnAttestationPayload(): array
{
    $coseKey = MapObject::create()
        ->add(UnsignedIntegerObject::create(1), UnsignedIntegerObject::create(2))
        ->add(UnsignedIntegerObject::create(3), NegativeIntegerObject::create(-7))
        ->add(NegativeIntegerObject::create(-1), UnsignedIntegerObject::create(1))
        ->add(NegativeIntegerObject::create(-2), ByteStringObject::create(str_repeat("\x01", 32)))
        ->add(NegativeIntegerObject::create(-3), ByteStringObject::create(str_repeat("\x02", 32)));

    $authData = str_repeat("\x00", 32).chr(0x41).pack('N', 0)
        .str_repeat("\x00", 16).pack('n', 4).'cred'
        .$coseKey;

    $attestationObject = (string) MapObject::create()
        ->add(TextStringObject::create('fmt'), TextStringObject::create('none'))
        ->add(TextStringObject::create('attStmt'), MapObject::create())
        ->add(TextStringObject::create('authData'), ByteStringObject::create($authData));

    return [
        'id' => 'Y3JlZA',
        'rawId' => 'Y3JlZA',
        'type' => 'public-key',
        'authenticatorAttachment' => null,
        'response' => [
            'clientDataJSON' => Base64UrlSafe::encodeUnpadded((string) json_encode([
                'type' => 'webauthn.create', 'challenge' => 'AQIDBA', 'origin' => 'http://localhost',
            ])),
            'attestationObject' => Base64UrlSafe::encodeUnpadded($attestationObject),
        ],
    ];
}

it('enrolls and confirms a TOTP factor, storing the secret encrypted and backfilling recovery codes', function (): void {
    $sink = fakeAudit();
    $enrollment = enrolling($this)
        ->postJson(route('identity.two-factor.enroll', ['provider' => 'totp']))
        ->assertCreated()
        ->json();

    $factor = TotpFactor::query()->firstOrFail();

    expect($enrollment['provider'])->toBe('totp')
        ->and($factor->user_id)->toBe((string) $this->user->id)
        ->and($factor->confirmed_at)->toBeNull()
        ->and($enrollment['metadata']['secret'])->toBe($factor->secret)
        ->and($enrollment['metadata']['qr_svg'])->toContain('<svg')
        ->and($enrollment['metadata']['qr_url'])->toContain('otpauth://')
        ->and(DB::table('oidc_totp_factors')->value('secret'))->not->toBe($factor->secret);

    enrolling($this)
        ->postJson(route('identity.two-factor.enroll.confirm', ['provider' => 'totp']), [
            'enrollment_id' => $enrollment['id'],
            'code' => '000000',
        ])->assertUnprocessable();

    expect($factor->refresh()->confirmed_at)->toBeNull();

    DB::transaction(function () use ($enrollment, $factor, $sink): void {
        enrolling($this)
            ->postJson(route('identity.two-factor.enroll.confirm', ['provider' => 'totp']), [
                'enrollment_id' => $enrollment['id'],
                'code' => app(Google2FA::class)->getCurrentOtp($factor->secret),
            ])->assertOk();
        $sink->assertNotRecorded(AuditEventType::FactorConfirmed);
    });
    $sink->assertRecorded(AuditEventType::FactorConfirmed);

    expect($factor->refresh()->confirmed_at)->not->toBeNull()
        ->and($this->user->recoveryCodes()->count())->toBe(8);
});

it('returns the existing pending enrollment instead of stacking rows, but starts a fresh one beside a confirmed factor', function (): void {
    $first = enrolling($this)->postJson(route('identity.two-factor.enroll', ['provider' => 'totp']))->json();
    $second = enrolling($this)->postJson(route('identity.two-factor.enroll', ['provider' => 'totp']))->assertCreated()->json();

    expect($this->user->totpFactors()->count())->toBe(1)
        ->and($second['id'])->toBe($first['id'])
        ->and($second['metadata']['secret'])->toBe($first['metadata']['secret']);

    TotpFactor::query()->whereKey($first['id'])->update(['confirmed_at' => now()]);

    $third = enrolling($this)->postJson(route('identity.two-factor.enroll', ['provider' => 'totp']))->assertCreated()->json();

    expect($this->user->totpFactors()->count())->toBe(2)
        ->and($third['id'])->not->toBe($first['id']);
});

it('lists enrollments across providers, regenerates recovery codes and revokes factors', function (): void {
    $enrollmentId = enrollConfirmedTotp($this);
    $originalCodes = $this->user->recoveryCodes()->pluck('code')->all();

    $regenerated = enrolling($this)
        ->postJson(route('identity.two-factor.enroll', ['provider' => 'recovery_code']))
        ->assertCreated()
        ->json();

    expect($regenerated['metadata']['codes'])->toHaveCount(8)->not->toBe($originalCodes);

    /** @var list<array{provider: string, metadata: array<string, mixed>}> $listing */
    $listing = enrolling($this)->getJson(route('identity.two-factor.factors'))->assertOk()->json('factors');
    $byProvider = collect($listing)->groupBy('provider');

    expect($byProvider->keys()->all())->toEqualCanonicalizing(['totp', 'recovery_code'])
        ->and($byProvider['recovery_code'][0]['metadata'])->toBe([]);

    enrolling($this)
        ->deleteJson(route('identity.two-factor.revoke', ['provider' => 'totp', 'enrollment' => $enrollmentId]))
        ->assertNoContent();

    expect($this->user->totpFactors()->count())->toBe(0)
        ->and($this->user->recoveryCodes()->count())->toBe(0);
});

it('requires authentication and a recent password confirmation', function (): void {
    $this->postJson(route('identity.two-factor.enroll', ['provider' => 'totp']))->assertUnauthorized();

    $this->actingAs($this->user, 'identity')
        ->post(route('identity.two-factor.enroll', ['provider' => 'totp']))
        ->assertRedirect(route('identity.password.confirm'));

    expect($this->user->totpFactors()->exists())->toBeFalse();
});

it('returns 404 for an unknown provider and rejects an option that belongs to another provider', function (): void {
    enrolling($this)->postJson(route('identity.two-factor.enroll', ['provider' => 'sms']))->assertNotFound();

    enrolling($this)
        ->postJson(route('identity.two-factor.enroll', ['provider' => 'totp']), ['option' => 'passkey'])
        ->assertUnprocessable()
        ->assertJsonValidationErrors('option');

    expect($this->user->totpFactors()->count())->toBe(0);
});

it('removes provider-owned factors when the authenticatable is deleted', function (): void {
    enrollConfirmedTotp($this);

    $this->user->delete();

    expect(DB::table('oidc_totp_factors')->count())->toBe(0)
        ->and(DB::table('oidc_recovery_codes')->count())->toBe(0);
});

it('enrolls a passkey through the generic webauthn ceremony', function (): void {
    config(['passkeys.user_handle_secret' => 'user-handle-secret']);

    // The attestation validation itself belongs to laravel/passkeys; stub the
    // store action (before the provider singleton captures the real one) to
    // observe the handoff.
    app()->instance(StorePasskey::class, new class($this->user) extends StorePasskey
    {
        public function __construct(private readonly User $owner) {}

        public function __invoke(
            Authenticatable $user,
            string $name,
            PublicKeyCredential $credential,
            PublicKeyCredentialCreationOptions $options
        ): Passkey {
            return $this->owner->passkeys()->create([
                'name' => $name,
                'credential_id' => 'stub-credential',
                'credential' => [],
            ]);
        }
    });

    $begin = enrolling($this)
        ->postJson(route('identity.two-factor.enroll', ['provider' => 'webauthn']), ['name' => 'Yubikey'])
        ->assertCreated()
        ->json();

    expect($begin['id'])->toBe('pending')
        ->and($begin['metadata']['options'])->toBeArray()
        ->and(session('oidc.webauthn.enrollment'))->toBeArray();

    enrolling($this)
        ->postJson(route('identity.two-factor.enroll.confirm', ['provider' => 'webauthn']), [
            'enrollment_id' => 'pending',
            'credential' => webauthnAttestationPayload(),
        ])->assertOk();

    $passkey = $this->user->passkeys()->firstOrFail();

    expect($passkey->name)->toBe('Yubikey')
        ->and(session('oidc.webauthn.enrollment'))->toBeNull()
        ->and($this->user->recoveryCodes()->count())->toBeGreaterThan(0);

    enrolling($this)->getJson(route('identity.two-factor.factors'))->assertOk()->assertJsonFragment(['provider' => 'webauthn']);

    enrolling($this)
        ->deleteJson(route('identity.two-factor.revoke', ['provider' => 'webauthn', 'enrollment' => $passkey->getKey()]))
        ->assertNoContent();

    expect($this->user->passkeys()->count())->toBe(0);
});

it('asks the browser for the authenticator the chosen option names', function (): void {
    config(['passkeys.user_handle_secret' => 'user-handle-secret']);

    $securityKey = enrolling($this)
        ->postJson(route('identity.two-factor.enroll', ['provider' => 'webauthn']), ['option' => 'security_key'])
        ->assertCreated()
        ->json();

    $unconstrained = enrolling($this)
        ->postJson(route('identity.two-factor.enroll', ['provider' => 'webauthn']))
        ->assertCreated()
        ->json();

    expect($securityKey['metadata']['options']['authenticatorSelection']['authenticatorAttachment'])->toBe('cross-platform')
        ->and($unconstrained['metadata']['options']['authenticatorSelection'])->not->toHaveKey('authenticatorAttachment');
});
