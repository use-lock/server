<?php

declare(strict_types=1);

namespace Lock\Server\Consents\Models;

use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Lock\Server\Database\Factories\ConsentFactory;
use Lock\Server\Shared\Realms\BelongsToRealm;

/**
 * What a user has approved for a client at one resource: the union of every
 * scope set they consented to there, kept until it is withdrawn.
 *
 * The resource is part of the identity of a consent. A scope name only means
 * something at the resource that declares it, so an approval of `read` at one
 * resource server says nothing about `read` at another.
 *
 * @property string $id
 * @property string $realm
 * @property string $user_id
 * @property string $client_id The client's primary key.
 * @property string $resource The resource identifier the scopes were approved for.
 * @property list<string> $scopes
 * @property CarbonInterface $granted_at
 * @property ?CarbonInterface $revoked_at
 * @property CarbonInterface $created_at
 * @property CarbonInterface $updated_at
 */
class Consent extends Model
{
    use BelongsToRealm, HasUuids;

    /** @use HasFactory<ConsentFactory> */
    use HasFactory;

    protected $table = 'oidc_consents';

    protected $guarded = [];

    protected static function newFactory(): ConsentFactory
    {
        return ConsentFactory::new();
    }

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'scopes' => 'array',
            'granted_at' => 'datetime',
            'revoked_at' => 'datetime',
        ];
    }

    public function isActive(): bool
    {
        return $this->revoked_at === null;
    }

    /** @param  list<string>  $scopes */
    public function covers(array $scopes): bool
    {
        return $this->isActive() && array_diff($scopes, $this->scopes) === [];
    }
}
