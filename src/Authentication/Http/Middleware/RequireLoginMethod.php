<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Lock\Server\Shared\Realms\RealmResolver;
use Lock\Server\Shared\Realms\Settings\LoginMethod;
use Symfony\Component\HttpFoundation\Response;

/**
 * Closes the routes of a login method the realm does not accept. A method
 * left out of `AuthenticationSettings::$methods` is refused here rather than
 * merely hidden from the login page, so a hand-built request cannot walk past
 * the realm's policy.
 *
 * Sitting in the route definition rather than in each controller is what lets
 * it cover the passkey endpoints, whose controllers belong to laravel/passkeys.
 */
class RequireLoginMethod
{
    public function __construct(private readonly RealmResolver $realms) {}

    public function handle(Request $request, Closure $next, string $method): Response
    {
        // A method the realm does not offer is disabled, not broken — so 404,
        // matching how registration without a bound action answers.
        abort_unless(
            $this->realms->current()->authentication()->allows(LoginMethod::from($method)),
            404,
        );

        return $next($request);
    }
}
