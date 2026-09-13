<?php

declare(strict_types=1);

namespace Lock\Server\Sessions;

/**
 * Names the single guard that owns the first-party session token. The mint
 * provider and the Login/Logout listeners must all resolve the guard through
 * here — a login on any other guard (e.g. an admin panel) must neither mint,
 * overwrite, nor revoke the token.
 */
final class SessionTokenGuard
{
    /**
     * Not IdentityGuard::name(): an explicitly null `oidc.auth.guard` has to
     * fall through to the application's default guard, which that method's
     * string cast would turn into an empty name instead.
     */
    public static function name(): ?string
    {
        $guard = config('oidc.session.token.guard')
            ?? config('oidc.auth.guard', 'identity')
            ?? config('auth.defaults.guard');

        return is_string($guard) && $guard !== '' ? $guard : null;
    }
}
