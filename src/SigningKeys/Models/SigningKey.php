<?php

declare(strict_types=1);

namespace Lock\Server\SigningKeys\Models;

use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Lock\Server\Shared\Realms\BelongsToRealm;
use Lock\Server\SigningKeys\SigningKeyPair;

/**
 * @property string $id
 * @property string $realm
 * @property string $kid
 * @property string $public_key
 * @property ?string $private_key
 * @property ?CarbonInterface $retired_at
 * @property ?CarbonInterface $created_at
 *
 * @method static Builder<static> query()
 */
class SigningKey extends Model
{
    use BelongsToRealm, HasUuids;

    protected $table = 'oidc_signing_keys';

    protected $guarded = [];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'private_key' => 'encrypted',
            'retired_at' => 'datetime',
        ];
    }

    public function toSigningKey(): SigningKeyPair
    {
        return new SigningKeyPair($this->public_key, $this->private_key, $this->kid);
    }

    public function toVerificationKey(): SigningKeyPair
    {
        return new SigningKeyPair($this->public_key, null, $this->kid);
    }
}
