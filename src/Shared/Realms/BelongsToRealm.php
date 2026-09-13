<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Realms;

use Illuminate\Database\Eloquent\Builder;

/**
 * Explicit scoping keeps cross-realm administration visible at each call site.
 */
trait BelongsToRealm
{
    /**
     * @param  Builder<static>  $query
     * @return Builder<static>
     */
    public function scopeInRealm(Builder $query, ?string $realm = null): Builder
    {
        return $query->where($this->getTable().'.realm', $realm ?? self::currentRealm());
    }

    public static function currentRealm(): string
    {
        return app(RealmResolver::class)->current()->identifier();
    }
}
