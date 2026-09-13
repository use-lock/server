<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\Http\Middleware;

use Closure;
use Illuminate\Auth\Middleware\RequirePassword;
use Lock\Server\Authentication\RequiredActions\PendingRequiredActions;
use Symfony\Component\HttpFoundation\Response;

/**
 * Laravel's password confirmation, minus the case it cannot serve. Enrolling
 * a factor from a live session is worth re-proving a credential for — it is
 * how a stolen session would lock the real owner out. Mid-login there is no
 * session to steal and no way to confirm one: the user proved a credential
 * seconds ago, and a login that arrived by passkey or upstream provider has
 * no password to recite.
 */
final class ConfirmPassword extends RequirePassword
{
    public function handle($request, Closure $next, $redirectToRoute = null, $passwordTimeoutSeconds = null): Response
    {
        if (PendingRequiredActions::find() instanceof PendingRequiredActions) {
            return $next($request);
        }

        return parent::handle($request, $next, $redirectToRoute, $passwordTimeoutSeconds);
    }
}
