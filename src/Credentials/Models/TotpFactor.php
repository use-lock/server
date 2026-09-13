<?php

declare(strict_types=1);

namespace Lock\Server\Credentials\Models;

use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Lock\Server\Database\Factories\TotpFactorFactory;

/**
 * @property string $id
 * @property string $user_id
 * @property string $name
 * @property string $secret
 * @property int|null $last_used_timestep
 * @property CarbonInterface|null $confirmed_at
 * @property CarbonInterface|null $last_used_at
 */
class TotpFactor extends Model
{
    /** @use HasFactory<TotpFactorFactory> */
    use HasFactory;

    use HasUuids;

    protected $table = 'oidc_totp_factors';

    protected $guarded = [];

    protected $hidden = [
        'secret',
    ];

    protected static function newFactory(): TotpFactorFactory
    {
        return TotpFactorFactory::new();
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'secret' => 'encrypted',
            'confirmed_at' => 'datetime',
            'last_used_at' => 'datetime',
            'last_used_timestep' => 'integer',
        ];
    }
}
