<?php

declare(strict_types=1);

namespace Lock\Server\Credentials;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Lock\Server\Credentials\Models\RecoveryCode;
use Lock\Server\Shared\Credentials\EnrollableFactorProvider;
use Lock\Server\Shared\Credentials\EnrollmentOption;
use Lock\Server\Shared\Credentials\FactorChallenge;
use Lock\Server\Shared\Credentials\FactorEnrollment;
use Lock\Server\Shared\Credentials\FactorVerification;
use Lock\Server\Shared\Realms\RealmResolver;
use LogicException;

class RecoveryCodeProvider implements EnrollableFactorProvider
{
    public function __construct(private readonly RealmResolver $realms) {}

    public function key(): string
    {
        return 'recovery_code';
    }

    public function isBackup(): bool
    {
        return true;
    }

    /**
     * Recovery codes are backfilled after confirmation, never chosen as a primary method.
     *
     * @return list<EnrollmentOption>
     */
    public function enrollmentOptions(): array
    {
        return [];
    }

    /**
     * @return list<string>
     */
    public function generate(Authenticatable $user): array
    {
        $codes = collect()->times(
            $this->realms->current()->credentials()->recoveryCodes,
            static fn (): string => Str::random(10).'-'.Str::random(10),
        )->all();

        DB::transaction(function () use ($user, $codes): void {
            $this->recoveryCodes($user)->delete();
            $this->recoveryCodes($user)->createMany(array_map(
                static fn (string $code): array => ['code' => $code],
                $codes,
            ));
        });

        return $codes;
    }

    /**
     * @return list<string>
     */
    public function codes(Authenticatable $user): array
    {
        return $this->recoveryCodes($user)
            ->whereNull('used_at')
            ->pluck('code')
            ->all();
    }

    /**
     * Count persisted codes because configuration may have changed since generation.
     */
    public function remaining(Authenticatable $user): int
    {
        return $this->recoveryCodes($user)->whereNull('used_at')->count();
    }

    public function total(Authenticatable $user): int
    {
        return $this->recoveryCodes($user)->count();
    }

    /**
     * EnrollmentPolicy keeps these account-wide codes until the last confirmed factor is removed.
     *
     * @return list<FactorEnrollment>
     */
    public function enrollments(Authenticatable $user): array
    {
        if (! $this->recoveryCodes($user)->exists()) {
            return [];
        }

        return [new FactorEnrollment($this->key(), 'account', 'Recovery code', now(), null)];
    }

    /**
     * Secret codes appear only in the enrollment response, never in enrollments().
     */
    public function beginEnrollment(Authenticatable $user, ?EnrollmentOption $option = null, ?string $name = null): FactorEnrollment
    {
        return new FactorEnrollment($this->key(), 'account', 'Recovery code', now(), null, [
            'codes' => $this->generate($user),
        ]);
    }

    /**
     * @param  array<string, mixed>  $input
     */
    public function confirmEnrollment(Authenticatable $user, FactorEnrollment $enrollment, array $input): bool
    {
        return true;
    }

    public function revoke(Authenticatable $user, FactorEnrollment $enrollment): void
    {
        $this->clear($user);
    }

    public function clear(Authenticatable $user): void
    {
        $this->recoveryCodes($user)->delete();
    }

    public function beginChallenge(Authenticatable $user, FactorEnrollment $enrollment): FactorChallenge
    {
        return new FactorChallenge($enrollment, ['input' => 'recovery_code']);
    }

    /**
     * @param  array<string, mixed>  $input
     */
    public function verify(Authenticatable $user, FactorChallenge $challenge, array $input): FactorVerification
    {
        $submittedCode = $input['recovery_code'] ?? null;

        if (! is_string($submittedCode) || $submittedCode === '') {
            return new FactorVerification(false);
        }

        $lockKey = 'oidc.recovery_codes.'.md5($user::class.':'.$user->getAuthIdentifier());
        $verified = Cache::lock($lockKey, 10)->block(10, fn (): bool => DB::transaction(function () use ($user, $submittedCode): bool {
            $codes = $this->recoveryCodes($user)->whereNull('used_at')->lockForUpdate()->get();

            foreach ($codes as $code) {
                if (! hash_equals($code->code, $submittedCode)) {
                    continue;
                }

                $code->forceFill(['used_at' => now()])->save();

                return true;
            }

            return false;
        }));

        return new FactorVerification($verified, $verified ? ['otp'] : []);
    }

    /**
     * @return HasMany<RecoveryCode, covariant Model>
     */
    private function recoveryCodes(Authenticatable $user): HasMany
    {
        if (! $user instanceof Model) {
            throw new LogicException('The authenticatable must be an Eloquent model to store recovery codes.');
        }

        return $user->hasMany(RecoveryCode::class, 'user_id');
    }
}
