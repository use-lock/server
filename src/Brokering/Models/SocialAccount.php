<?php

declare(strict_types=1);

namespace Lock\Server\Brokering\Models;

use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Lock\Server\Database\Factories\SocialAccountFactory;
use Lock\Server\Shared\Realms\BelongsToRealm;

/**
 * @property string $id
 * @property string $realm
 * @property string $user_id
 * @property string $provider
 * @property string $provider_user_id
 * @property string|null $email
 * @property string|null $name
 * @property string|null $nickname
 * @property string|null $avatar
 * @property string|null $access_token
 * @property string|null $refresh_token
 * @property CarbonInterface|null $token_expires_at
 * @property array<string, mixed>|null $raw
 */
class SocialAccount extends Model
{
    use BelongsToRealm, HasUuids;

    /** @use HasFactory<SocialAccountFactory> */
    use HasFactory;

    protected $table = 'oidc_social_accounts';

    protected $guarded = [];

    protected $hidden = [
        'access_token',
        'refresh_token',
    ];

    protected static function newFactory(): SocialAccountFactory
    {
        return SocialAccountFactory::new();
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'access_token' => 'encrypted',
            'refresh_token' => 'encrypted',
            'token_expires_at' => 'datetime',
            'raw' => 'array',
        ];
    }
}
