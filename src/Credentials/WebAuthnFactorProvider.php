<?php

declare(strict_types=1);

namespace Lock\Server\Credentials;

use Illuminate\Contracts\Auth\Authenticatable;
use Laravel\Passkeys\Actions\GenerateRegistrationOptions;
use Laravel\Passkeys\Actions\GenerateVerificationOptions;
use Laravel\Passkeys\Actions\StorePasskey;
use Laravel\Passkeys\Actions\VerifyPasskey;
use Laravel\Passkeys\Contracts\PasskeyUser;
use Laravel\Passkeys\Passkey;
use Laravel\Passkeys\Support\WebAuthn;
use Lock\Server\Credentials\WebAuthn\AttachmentAwareRegistrationOptions;
use Lock\Server\Shared\Credentials\EnrollableFactorProvider;
use Lock\Server\Shared\Credentials\EnrollmentOption;
use Lock\Server\Shared\Credentials\FactorChallenge;
use Lock\Server\Shared\Credentials\FactorEnrollment;
use Lock\Server\Shared\Credentials\FactorRole;
use Lock\Server\Shared\Credentials\FactorSetupKind;
use Lock\Server\Shared\Credentials\FactorVerification;
use Throwable;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRequestOptions;

/**
 * WebAuthn options remain in the session until confirmation stores the credential.
 */
class WebAuthnFactorProvider implements EnrollableFactorProvider
{
    private const string PENDING_KEY = 'oidc.webauthn.enrollment';

    private const string PENDING_ID = 'pending';

    public function __construct(
        private readonly GenerateVerificationOptions $generateOptions,
        private readonly VerifyPasskey $verifyPasskey,
        private readonly GenerateRegistrationOptions $generateRegistrationOptions,
        private readonly StorePasskey $storePasskey,
    ) {}

    public function key(): string
    {
        return 'webauthn';
    }

    public function isBackup(): bool
    {
        return false;
    }

    /**
     * Platform and roaming authenticators share storage and verification; only attachment differs.
     *
     * @return list<EnrollmentOption>
     */
    public function enrollmentOptions(): array
    {
        return [
            new EnrollmentOption(
                id: 'passkey',
                providerKey: $this->key(),
                role: FactorRole::LoginAndSecondFactor,
                setupKind: FactorSetupKind::Ceremony,
                recommended: true,
                sortOrder: 10,
                hints: ['attachment' => AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_PLATFORM],
            ),
            new EnrollmentOption(
                id: 'security_key',
                providerKey: $this->key(),
                role: FactorRole::LoginAndSecondFactor,
                setupKind: FactorSetupKind::Ceremony,
                sortOrder: 20,
                hints: ['attachment' => AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM],
            ),
        ];
    }

    /**
     * @return list<FactorEnrollment>
     */
    public function enrollments(Authenticatable $user): array
    {
        if (! $user instanceof PasskeyUser) {
            return [];
        }

        $enrollments = $user->passkeys()->get()->map(fn (Passkey $passkey): FactorEnrollment => new FactorEnrollment(
            $this->key(),
            (string) $passkey->getKey(),
            $passkey->name,
            $passkey->created_at,
            $passkey->last_used_at,
            [
                'authenticator' => $passkey->authenticator,
                'credential_id' => $passkey->credential_id,
            ],
        ))->all();

        $pending = session()->get(self::PENDING_KEY);

        if (is_array($pending)) {
            $enrollments[] = new FactorEnrollment(
                $this->key(),
                self::PENDING_ID,
                (string) ($pending['name'] ?? 'Passkey'),
                null,
                null,
            );
        }

        return $enrollments;
    }

    /**
     * Reuse options for the same choice so an in-flight ceremony keeps its challenge.
     */
    public function beginEnrollment(Authenticatable $user, ?EnrollmentOption $option = null, ?string $name = null): FactorEnrollment
    {
        if (! $user instanceof PasskeyUser) {
            abort(403);
        }

        $pending = session()->get(self::PENDING_KEY);
        $reusable = is_array($pending) && ($pending['option'] ?? null) === $option?->id;

        $serialized = $reusable
            ? (string) $pending['options']
            : WebAuthn::toJson(($this->registrationOptionsFor($option))($user));

        $name ??= $reusable ? (string) ($pending['name'] ?? 'Passkey') : 'Passkey';

        session()->put(self::PENDING_KEY, [
            'options' => $serialized,
            'name' => $name,
            'option' => $option?->id,
        ]);

        return new FactorEnrollment(
            $this->key(),
            self::PENDING_ID,
            $name,
            null,
            null,
            ['options' => WebAuthn::toBrowserArray(
                WebAuthn::fromJson($serialized, PublicKeyCredentialCreationOptions::class),
            )],
        );
    }

    /**
     * @param  array<string, mixed>  $input
     */
    public function confirmEnrollment(Authenticatable $user, FactorEnrollment $enrollment, array $input): bool
    {
        $pending = session()->get(self::PENDING_KEY);
        $credential = $input['credential'] ?? null;

        if ($enrollment->id !== self::PENDING_ID || ! is_array($pending) || ! is_array($credential)) {
            return false;
        }

        // The user may enter the label after the ceremony begins.
        $submittedName = $input['name'] ?? null;
        $name = is_string($submittedName) && trim($submittedName) !== ''
            ? trim($submittedName)
            : (string) ($pending['name'] ?? 'Passkey');

        try {
            ($this->storePasskey)(
                $user,
                $name,
                WebAuthn::fromJson((string) json_encode($credential), PublicKeyCredential::class),
                WebAuthn::fromJson((string) $pending['options'], PublicKeyCredentialCreationOptions::class),
            );
        } catch (Throwable) {
            return false;
        }

        session()->forget(self::PENDING_KEY);

        return true;
    }

    public function revoke(Authenticatable $user, FactorEnrollment $enrollment): void
    {
        if ($enrollment->id === self::PENDING_ID) {
            session()->forget(self::PENDING_KEY);

            return;
        }

        if ($user instanceof PasskeyUser) {
            $user->passkeys()->whereKey($enrollment->id)->delete();
        }
    }

    public function beginChallenge(Authenticatable $user, FactorEnrollment $enrollment): FactorChallenge
    {
        if (! $user instanceof PasskeyUser) {
            return new FactorChallenge($enrollment);
        }

        $options = ($this->generateOptions)($user);

        return new FactorChallenge(
            $enrollment,
            ['options' => WebAuthn::toBrowserArray($options)],
            ['options' => WebAuthn::toJson($options)],
        );
    }

    /**
     * @param  array<string, mixed>  $input
     */
    public function verify(Authenticatable $user, FactorChallenge $challenge, array $input): FactorVerification
    {
        if (! $user instanceof PasskeyUser) {
            return new FactorVerification(false);
        }

        $credential = $input['credential'] ?? null;
        $serializedOptions = $challenge->privateState['options'] ?? null;

        if (! is_array($credential) || ! is_string($serializedOptions)) {
            return new FactorVerification(false);
        }

        try {
            // Options allow all of the user's passkeys; VerifyPasskey enforces ownership.
            ($this->verifyPasskey)(
                WebAuthn::fromJson((string) json_encode($credential), PublicKeyCredential::class),
                WebAuthn::fromJson($serializedOptions, PublicKeyCredentialRequestOptions::class),
                $user,
            );
        } catch (Throwable) {
            return new FactorVerification(false);
        }

        return new FactorVerification(true, ['webauthn']);
    }

    /**
     * Preserve host action customizations when no attachment is requested.
     */
    private function registrationOptionsFor(?EnrollmentOption $option): GenerateRegistrationOptions
    {
        $attachment = $option?->hints['attachment'] ?? null;

        return is_string($attachment)
            ? new AttachmentAwareRegistrationOptions($attachment)
            : $this->generateRegistrationOptions;
    }
}
