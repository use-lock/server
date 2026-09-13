<?php

declare(strict_types=1);

namespace Lock\Server\Tokens\Models;

use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Lock\Server\Database\Factories\AuthorizationCodeFactory;
use Lock\Server\Shared\Realms\BelongsToRealm;
use Lock\Server\Tokens\Concerns\PrunesSpentRecords;

/**
 * @property string $id
 * @property string $code The secret the browser carries back from the redirect.
 * @property string $realm
 * @property string $user_id
 * @property string $client_id
 * @property array<int, string> $scopes
 * @property ?array<int, string> $audience The RFC 8707 resources requested at authorization; empty for the realm default.
 * @property ?string $redirect_uri
 * @property string $code_challenge
 * @property string $code_challenge_method
 * @property ?string $nonce
 * @property ?int $auth_time
 * @property ?string $context_id
 * @property ?CarbonInterface $revoked_at
 * @property ?CarbonInterface $expires_at
 * @property CarbonInterface $created_at
 * @property CarbonInterface $updated_at
 */
class AuthorizationCode extends Model
{
    use BelongsToRealm, HasUuids;

    /** @use HasFactory<AuthorizationCodeFactory> */
    use HasFactory;

    use PrunesSpentRecords;

    protected $table = 'oidc_auth_codes';

    protected $guarded = [];

    protected $hidden = ['code'];

    protected static function newFactory(): AuthorizationCodeFactory
    {
        return AuthorizationCodeFactory::new();
    }

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'scopes' => 'array',
            'audience' => 'array',
            'auth_time' => 'integer',
            'revoked_at' => 'datetime',
            'expires_at' => 'datetime',
        ];
    }

    public function issuedTo(string $clientKey): bool
    {
        return (string) $this->client_id === $clientKey;
    }

    public function isRevoked(): bool
    {
        return $this->revoked_at !== null;
    }
}
