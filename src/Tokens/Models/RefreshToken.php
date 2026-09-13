<?php

declare(strict_types=1);

namespace Lock\Server\Tokens\Models;

use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Lock\Server\Database\Factories\RefreshTokenFactory;
use Lock\Server\Shared\Realms\BelongsToRealm;
use Lock\Server\Tokens\Concerns\PrunesSpentRecords;

/**
 * @property string $id
 * @property string $realm
 * @property string $access_token_id
 * @property ?CarbonInterface $revoked_at
 * @property ?CarbonInterface $expires_at
 * @property CarbonInterface $created_at
 * @property CarbonInterface $updated_at
 */
class RefreshToken extends Model
{
    use BelongsToRealm;

    /** @use HasFactory<RefreshTokenFactory> */
    use HasFactory;

    use PrunesSpentRecords;

    protected $table = 'oidc_refresh_tokens';

    protected $primaryKey = 'id';

    protected $keyType = 'string';

    public $incrementing = false;

    protected $guarded = [];

    protected static function newFactory(): RefreshTokenFactory
    {
        return RefreshTokenFactory::new();
    }

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'revoked_at' => 'datetime',
            'expires_at' => 'datetime',
        ];
    }

    /** @return BelongsTo<AccessToken, $this> */
    public function accessToken(): BelongsTo
    {
        return $this->belongsTo(AccessToken::class, 'access_token_id');
    }

    public function isRevoked(): bool
    {
        return $this->revoked_at !== null;
    }
}
