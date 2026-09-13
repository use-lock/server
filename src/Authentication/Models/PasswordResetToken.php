<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\Models;

use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\MassPrunable;
use Illuminate\Database\Eloquent\Model;
use Lock\Server\Database\Factories\PasswordResetTokenFactory;
use Lock\Server\Shared\Realms\BelongsToRealm;
use Lock\Server\Shared\Realms\CurrentRealm;
use Lock\Server\Shared\Realms\RealmResolver;

/**
 * @property string $id
 * @property string $realm
 * @property string $user_id
 * @property string $token
 * @property CarbonInterface $created_at
 */
class PasswordResetToken extends Model
{
    use BelongsToRealm, HasUuids;
    use MassPrunable;

    public $timestamps = false;

    /** @use HasFactory<PasswordResetTokenFactory> */
    use HasFactory;

    protected $table = 'oidc_password_reset_tokens';

    protected $guarded = [];

    protected $hidden = ['token'];

    protected static function newFactory(): PasswordResetTokenFactory
    {
        return PasswordResetTokenFactory::new();
    }

    /** @return array<string, string> */
    protected function casts(): array
    {
        return ['created_at' => 'datetime'];
    }

    /** @return Builder<static> */
    public function prunable(): Builder
    {
        $realms = static::query()->distinct()->pluck('realm');

        return static::query()->where(function (Builder $query) use ($realms): void {
            $query->whereRaw('1 = 0');

            foreach ($realms as $realm) {
                $lifetime = CurrentRealm::runAs($realm, fn (): int => app(RealmResolver::class)->current()->tokens()->passwordResetLifetime);

                $query->orWhere(fn (Builder $query): Builder => $query
                    ->where('realm', $realm)
                    ->where('created_at', '<', now()->subSeconds($lifetime)));
            }
        });
    }
}
