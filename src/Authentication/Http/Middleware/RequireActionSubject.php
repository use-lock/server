<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\Http\Middleware;

use Closure;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Lock\Server\Shared\Authentication\IdentityGuard;
use Lock\Server\Shared\Authentication\LoginDestination;
use Lock\Server\Shared\Authentication\RequiredActionSubject;
use Symfony\Component\HttpFoundation\Response;

/**
 * Guards the screens that settle a required action. They are reachable both
 * from a live session and from a login that is still pending one, so they
 * cannot sit behind the identity guard: mid-login there is no session yet,
 * by design.
 */
class RequireActionSubject
{
    public function __construct(
        private readonly RequiredActionSubject $subject,
        private readonly LoginDestination $loginDestination,
    ) {}

    public function handle(Request $request, Closure $next): Response
    {
        if (! $this->subject->current($request) instanceof Authenticatable) {
            throw new AuthenticationException(
                guards: [IdentityGuard::name()],
                redirectTo: $this->loginDestination->url(),
            );
        }

        return $next($request);
    }
}
