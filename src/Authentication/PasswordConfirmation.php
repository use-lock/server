<?php

declare(strict_types=1);

namespace Lock\Server\Authentication;

use Illuminate\Contracts\Session\Session;

/**
 * The `auth.password_confirmed_at` session bookkeeping shared by the
 * password-confirmation endpoints and host apps that gate actions on a
 * recently confirmed password.
 */
final class PasswordConfirmation
{
    public static function confirm(Session $session): void
    {
        $session->put('auth.password_confirmed_at', time());
    }

    public static function confirmedRecently(Session $session): bool
    {
        $confirmedAt = (int) $session->get('auth.password_confirmed_at', 0);

        return (time() - $confirmedAt) < (int) config('auth.password_timeout', 900);
    }
}
