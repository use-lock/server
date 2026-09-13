<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Authentication;

/**
 * The identity guard is deployment-wide and cannot vary by realm.
 */
final class IdentityGuard
{
    public static function name(): string
    {
        return (string) config('oidc.auth.guard', 'identity');
    }
}
