<?php

declare(strict_types=1);

namespace Lock\Server\Credentials\Models;

use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Lock\Server\Database\Factories\RecoveryCodeFactory;

/**
 * @property string $id
 * @property string $user_id
 * @property string $code
 * @property CarbonInterface|null $used_at
 */
class RecoveryCode extends Model
{
    /** @use HasFactory<RecoveryCodeFactory> */
    use HasFactory;

    use HasUuids;

    protected $table = 'oidc_recovery_codes';

    protected $guarded = [];

    protected $hidden = [
        'code',
    ];

    protected static function newFactory(): RecoveryCodeFactory
    {
        return RecoveryCodeFactory::new();
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'code' => 'encrypted',
            'used_at' => 'datetime',
        ];
    }
}
