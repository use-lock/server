<?php

declare(strict_types=1);

namespace Lock\Server\Tokens\Http\Middleware;

use BackedEnum;
use Closure;
use Illuminate\Http\Request;
use Lock\Server\Shared\Protocol\OAuthServerException;
use Lock\Server\Shared\Realms\RealmAudiences;
use Lock\Server\Shared\Tokens\AccessTokenBearer;
use Lock\Server\Tokens\Guard\CurrentAccessToken;
use Symfony\Component\HttpFoundation\Response;

/**
 * Requires a preceding guard that populates currentAccessToken().
 * An audience mismatch is invalid_token, not insufficient_scope (RFC 6750 §3.1).
 *
 * A path-relative resource identifier (`api`, or an enum backed by one)
 * resolves under the current realm's issuer at request time, so a route can
 * name a resource whose audience is only known once the realm is.
 */
class CheckAudience
{
    public function __construct(private readonly RealmAudiences $audiences) {}

    public static function using(string|BackedEnum ...$audiences): string
    {
        return static::class.':'.implode(',', array_map(
            static fn (string|BackedEnum $audience): string => $audience instanceof BackedEnum ? (string) $audience->value : $audience,
            $audiences,
        ));
    }

    public function handle(Request $request, Closure $next, string ...$audiences): Response
    {
        $user = $request->user();

        if (! $user instanceof AccessTokenBearer || ! $user->currentAccessToken() instanceof CurrentAccessToken) {
            throw OAuthServerException::invalidToken();
        }

        $tokenAudiences = (array) $request->attributes->get('oidc_token_audience', []);
        $expected = array_map($this->audiences->identifier(...), $audiences);

        if (array_intersect($expected, $tokenAudiences) === []) {
            throw OAuthServerException::invalidToken('The access token is not addressed to this resource.');
        }

        return $next($request);
    }
}
