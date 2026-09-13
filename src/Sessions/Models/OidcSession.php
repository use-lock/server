<?php

declare(strict_types=1);

namespace Lock\Server\Sessions\Models;

use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\MassPrunable;
use Illuminate\Database\Eloquent\Model;
use Lock\Server\Database\Factories\OidcSessionFactory;
use Lock\Server\Shared\Realms\BelongsToRealm;

/**
 * @property string $id
 * @property string $realm
 * @property string $user_id
 * @property ?string $browser_session_id The id of the browser session the login happened in.
 * @property CarbonInterface $created_at
 * @property CarbonInterface $updated_at
 * @property ?CarbonInterface $expires_at
 * @property ?CarbonInterface $revoked_at
 * @property ?CarbonInterface $logout_finished_at
 */
class OidcSession extends Model
{
    use BelongsToRealm, HasUuids;

    /** @use HasFactory<OidcSessionFactory> */
    use HasFactory;

    use MassPrunable;

    protected $table = 'oidc_sessions';

    protected $guarded = [];

    protected static function newFactory(): OidcSessionFactory
    {
        return OidcSessionFactory::new();
    }

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'expires_at' => 'datetime',
            'revoked_at' => 'datetime',
            'logout_finished_at' => 'datetime',
        ];
    }

    public function isActive(): bool
    {
        return $this->revoked_at === null
            && ($this->expires_at === null || $this->expires_at->isFuture());
    }

    public function logoutRetryExpired(): bool
    {
        $endedAt = $this->revoked_at;

        if ($endedAt === null || ($this->expires_at !== null && $this->expires_at->lessThan($endedAt))) {
            $endedAt = $this->expires_at;
        }

        return $endedAt !== null
            && $endedAt->copy()->addSeconds(max(0, (int) config('oidc.session.logout_retry_lifetime', 86400)))->isPast();
    }

    /** @return Builder<static> */
    public function prunable(): Builder
    {
        $grace = now()->subSeconds((int) config('oidc.pruning.sessions', 86400));

        return static::query()
            ->where(fn (Builder $query): Builder => $query->where('expires_at', '<', $grace)->orWhere('revoked_at', '<', $grace))
            ->where('logout_finished_at', '<', $grace);
    }
}
