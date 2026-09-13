<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Ui\Support;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Lock\Server\Shared\Authentication\RequiredActionSubject;

/**
 * Prefer the host's default guard for embedded account screens; mid-login,
 * only the pending login identifies the user.
 * Static because cloned custom fields cannot reach their owning definition.
 */
final class ScreenSubject
{
    /**
     * Factor providers build their own morph relations, so any Eloquent
     * authenticatable qualifies.
     */
    public static function current(): (Authenticatable&Model)|null
    {
        $user = auth()->user() ?? app(RequiredActionSubject::class)->current(request());

        return $user instanceof Model ? $user : null;
    }

    public static function currentOrFail(): Authenticatable&Model
    {
        return self::current() ?? abort(403);
    }
}
