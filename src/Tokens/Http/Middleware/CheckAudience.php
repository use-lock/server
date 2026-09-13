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
 * Requires a preceding guard that populates currentAccessToken().
 * An audience mismatch is invalid_token, not insufficient_scope (RFC 6750 §3.1).
 */
class CheckAudience
{
    public static function using(string ...$audiences): string
    {
        return static::class.':'.implode(',', $audiences);
    }

    public function handle(Request $request, Closure $next, string ...$audiences): Response
    {
        $user = $request->user();

        if (! $user instanceof AccessTokenBearer || ! $user->currentAccessToken() instanceof CurrentAccessToken) {
            throw OAuthServerException::invalidToken();
        }

        $tokenAudiences = (array) $request->attributes->get('oidc_token_audience', []);

        if (array_intersect($audiences, $tokenAudiences) === []) {
            throw OAuthServerException::invalidToken('The access token is not addressed to this resource.');
        }

        return $next($request);
    }
}
