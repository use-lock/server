<?php

declare(strict_types=1);

namespace Lock\Server\Tokens\Concerns;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\MassPrunable;
use Illuminate\Database\Eloquent\Model;

/**
 * A token is spent once it is revoked or expired, but introspection and audit
 * still read it for a while afterwards, so both are kept for `oidc.pruning.tokens`.
 *
 * @phpstan-require-extends Model
 */
trait PrunesSpentRecords
{
    use MassPrunable;

    /** @return Builder<static> */
    public function prunable(): Builder
    {
        $cutoff = now()->subSeconds((int) config('oidc.pruning.tokens', 604800));

        return static::query()
            ->where('revoked_at', '<', $cutoff)
            ->orWhere('expires_at', '<', $cutoff);
    }
}
