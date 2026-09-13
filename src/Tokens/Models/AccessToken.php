<?php

declare(strict_types=1);

namespace Lock\Server\Tokens\Models;

use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasOne;
use Lock\Server\Database\Factories\AccessTokenFactory;
use Lock\Server\Shared\Realms\BelongsToRealm;
use Lock\Server\Tokens\Concerns\PrunesSpentRecords;

/**
 * @property string $id The token's jti.
 * @property string $realm
 * @property ?string $user_id
 * @property string $client_id
 * @property ?string $name
 * @property ?array<string, mixed> $context Host-defined facts a directly issued access token was issued with, e.g. the tenant it is bound to.
 * @property array<int, string> $scopes
 * @property ?array<int, string> $audience The `aud` the token was minted with.
 * @property ?string $auth_code_id The authorization code this token, or the refresh chain it sits in, descends from. Not a foreign key: the chain outlives the code row.
 * @property ?string $context_id The authentication context the token was issued under; null for a non-interactive grant.
 * @property ?CarbonInterface $revoked_at
 * @property ?CarbonInterface $expires_at
 */
class AccessToken extends Model
{
    use BelongsToRealm;

    /** @use HasFactory<AccessTokenFactory> */
    use HasFactory;

    use PrunesSpentRecords;

    protected $table = 'oidc_access_tokens';

    protected $primaryKey = 'id';

    protected $keyType = 'string';

    public $incrementing = false;

    protected $guarded = [];

    protected static function newFactory(): AccessTokenFactory
    {
        return AccessTokenFactory::new();
    }

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'scopes' => 'array',
            'audience' => 'array',
            'context' => 'array',
            'revoked_at' => 'datetime',
            'expires_at' => 'datetime',
        ];
    }

    public function issuedTo(string $clientKey): bool
    {
        return (string) $this->client_id === $clientKey;
    }

    /** @return HasOne<RefreshToken, $this> */
    public function refreshToken(): HasOne
    {
        return $this->hasOne(RefreshToken::class, 'access_token_id');
    }

    public function isRevoked(): bool
    {
        return $this->revoked_at !== null;
    }

    public function isValid(): bool
    {
        return ! $this->isRevoked() && ($this->expires_at === null || $this->expires_at->isFuture());
    }

    public function hasScope(string $scope): bool
    {
        return in_array($scope, $this->scopes ?? [], true);
    }
}
