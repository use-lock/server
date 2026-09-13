<?php

declare(strict_types=1);

namespace Lock\Server\Credentials;

use BaconQrCode\Renderer\Image\SvgImageBackEnd;
use BaconQrCode\Renderer\ImageRenderer;
use BaconQrCode\Renderer\RendererStyle\RendererStyle;
use BaconQrCode\Writer;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Support\Facades\DB;
use Lock\Server\Credentials\Models\TotpFactor;
use Lock\Server\Shared\Credentials\EnrollableFactorProvider;
use Lock\Server\Shared\Credentials\EnrollmentOption;
use Lock\Server\Shared\Credentials\FactorChallenge;
use Lock\Server\Shared\Credentials\FactorEnrollment;
use Lock\Server\Shared\Credentials\FactorRole;
use Lock\Server\Shared\Credentials\FactorSetupKind;
use Lock\Server\Shared\Credentials\FactorVerification;
use Lock\Server\Shared\Realms\RealmResolver;
use LogicException;
use PragmaRX\Google2FA\Google2FA;

class TotpFactorProvider implements EnrollableFactorProvider
{
    public function __construct(
        private readonly Google2FA $engine,
        private readonly RealmResolver $realms,
    ) {}

    public function key(): string
    {
        return 'totp';
    }

    public function isBackup(): bool
    {
        return false;
    }

    /**
     * @return list<EnrollmentOption>
     */
    public function enrollmentOptions(): array
    {
        return [
            new EnrollmentOption(
                id: 'totp',
                providerKey: $this->key(),
                role: FactorRole::SecondFactorOnly,
                setupKind: FactorSetupKind::Code,
                sortOrder: 30,
            ),
        ];
    }

    public function enroll(Authenticatable $user, ?string $name = null): TotpFactor
    {
        return $this->factors($user)->create([
            'name' => $name ?? 'Authenticator app',
            'secret' => $this->engine->generateSecretKey($this->realms->current()->credentials()->totpSecretLength),
        ]);
    }

    /**
     * Reuse pending secrets on repeated enrollment requests; confirmed factors stay untouched.
     */
    public function beginEnrollment(Authenticatable $user, ?EnrollmentOption $option = null, ?string $name = null): FactorEnrollment
    {
        $factor = $this->latestPendingFactor($user) ?? $this->enroll($user, $name);
        $enrollment = $this->toEnrollment($factor);

        // The setup payload only exists at enrollment time; enrollments()
        // never exposes the secret again.
        return new FactorEnrollment(
            $enrollment->providerKey,
            $enrollment->id,
            $enrollment->label,
            $enrollment->confirmedAt,
            $enrollment->lastUsedAt,
            [
                'secret' => $factor->secret,
                'qr_svg' => $this->qrCodeSvg($factor, $user),
                'qr_url' => $this->qrCodeUrl($factor, $user),
            ],
        );
    }

    /**
     * @param  array<string, mixed>  $input
     */
    public function confirmEnrollment(Authenticatable $user, FactorEnrollment $enrollment, array $input): bool
    {
        $factor = $this->factorFor($user, $enrollment);
        $code = $input['code'] ?? null;

        if (! is_string($code) || ! $this->engine->verifyKey($factor->secret, $code, $this->window())) {
            return false;
        }

        $factor->forceFill(['confirmed_at' => now()])->save();

        return true;
    }

    public function revoke(Authenticatable $user, FactorEnrollment $enrollment): void
    {
        $this->factorFor($user, $enrollment)->delete();
    }

    public function latestFactor(Authenticatable $user): ?TotpFactor
    {
        return $this->factors($user)->latest('id')->first();
    }

    public function latestPendingFactor(Authenticatable $user): ?TotpFactor
    {
        return $this->factors($user)->whereNull('confirmed_at')->latest('id')->first();
    }

    /**
     * @return list<FactorEnrollment>
     */
    public function enrollments(Authenticatable $user): array
    {
        return $this->factors($user)->get()
            ->map(fn (TotpFactor $factor): FactorEnrollment => $this->toEnrollment($factor))
            ->all();
    }

    public function beginChallenge(Authenticatable $user, FactorEnrollment $enrollment): FactorChallenge
    {
        $this->factorFor($user, $enrollment);

        return new FactorChallenge($enrollment, ['input' => 'code']);
    }

    /**
     * @param  array<string, mixed>  $input
     */
    public function verify(Authenticatable $user, FactorChallenge $challenge, array $input): FactorVerification
    {
        $code = $input['code'] ?? null;

        if (! is_string($code) || $code === '') {
            return new FactorVerification(false);
        }

        $verified = DB::transaction(function () use ($user, $challenge, $code): bool {
            $factor = $this->factors($user)
                ->whereKey($challenge->enrollment->id)
                ->whereNotNull('confirmed_at')
                ->lockForUpdate()
                ->first();

            if (! $factor instanceof TotpFactor) {
                return false;
            }

            $timestamp = $this->engine->verifyKeyNewer(
                $factor->secret,
                $code,
                $factor->last_used_timestep,
                $this->window(),
            );

            if ($timestamp === false) {
                return false;
            }

            $factor->forceFill([
                'last_used_timestep' => $timestamp === true ? $this->engine->getTimestamp() : $timestamp,
                'last_used_at' => now(),
            ])->save();

            return true;
        });

        return new FactorVerification($verified, $verified ? ['otp'] : []);
    }

    public function qrCodeUrl(TotpFactor $factor, Authenticatable $user): string
    {
        $username = method_exists($user, 'getPasskeyUsername')
            ? $user->getPasskeyUsername()
            : (string) $user->getAuthIdentifier();

        return $this->engine->getQRCodeUrl((string) config('app.name'), $username, $factor->secret);
    }

    public function qrCodeSvg(TotpFactor $factor, Authenticatable $user): string
    {
        $writer = new Writer(new ImageRenderer(new RendererStyle(192, 0), new SvgImageBackEnd));

        return $writer->writeString($this->qrCodeUrl($factor, $user));
    }

    private function window(): int
    {
        return $this->realms->current()->credentials()->totpWindow;
    }

    private function factorFor(Authenticatable $user, FactorEnrollment $enrollment): TotpFactor
    {
        if ($enrollment->providerKey !== $this->key()) {
            throw new LogicException('The enrollment does not belong to the TOTP provider.');
        }

        return $this->factors($user)->whereKey($enrollment->id)->firstOrFail();
    }

    /**
     * @return HasMany<TotpFactor, covariant Model>
     */
    private function factors(Authenticatable $user): HasMany
    {
        if (! $user instanceof Model) {
            throw new LogicException('The authenticatable must be an Eloquent model to store TOTP factors.');
        }

        return $user->hasMany(TotpFactor::class, 'user_id');
    }

    private function toEnrollment(TotpFactor $factor): FactorEnrollment
    {
        return new FactorEnrollment(
            $this->key(),
            (string) $factor->getKey(),
            $factor->name,
            $factor->confirmed_at,
            $factor->last_used_at,
        );
    }
}
