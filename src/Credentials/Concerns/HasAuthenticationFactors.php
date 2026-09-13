<?php

declare(strict_types=1);

namespace Lock\Server\Credentials\Concerns;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Laravel\Passkeys\PasskeyAuthenticatable;
use Lock\Server\Credentials\Models\RecoveryCode;
use Lock\Server\Credentials\Models\TotpFactor;

/**
 * @mixin Model
 */
trait HasAuthenticationFactors
{
    use PasskeyAuthenticatable;

    protected static function bootHasAuthenticationFactors(): void
    {
        static::deleting(function (Model $authenticatable): void {
            $authenticatable->hasMany(TotpFactor::class, 'user_id')->delete();
            $authenticatable->hasMany(RecoveryCode::class, 'user_id')->delete();
        });
    }

    /**
     * @return HasMany<TotpFactor, $this>
     */
    public function totpFactors(): HasMany
    {
        return $this->hasMany(TotpFactor::class, 'user_id');
    }

    /**
     * @return HasMany<RecoveryCode, $this>
     */
    public function recoveryCodes(): HasMany
    {
        return $this->hasMany(RecoveryCode::class, 'user_id');
    }
}
