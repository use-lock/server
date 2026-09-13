<?php

declare(strict_types=1);

namespace Lock\Server\Tokens\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Lock\Server\Shared\Protocol\OAuthServerException;
use Lock\Server\Shared\Tokens\AccessTokenBearer;
use Lock\Server\Tokens\Guard\CurrentAccessToken;
use Symfony\Component\HttpFoundation\Response;

/**
 * Requires a preceding guard that populates currentAccessToken(), normally auth:oidc.
 */
class CheckScopes
{
    public static function using(string ...$scopes): string
    {
        return static::class.':'.implode(',', $scopes);
    }

    public function handle(Request $request, Closure $next, string ...$scopes): Response
    {
        $user = $request->user();

        if (! $user instanceof AccessTokenBearer || ! $user->currentAccessToken() instanceof CurrentAccessToken) {
            throw OAuthServerException::invalidToken();
        }

        foreach ($scopes as $scope) {
            if (! $user->currentAccessToken()->can($scope)) {
                throw OAuthServerException::insufficientScope();
            }
        }

        return $next($request);
    }
}
