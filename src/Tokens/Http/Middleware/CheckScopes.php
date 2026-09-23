<?php

declare(strict_types=1);

namespace Lock\Server\Tokens\Http\Middleware;

use BackedEnum;
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
    public static function using(string|BackedEnum ...$scopes): string
    {
        return static::class.':'.implode(',', array_map(
            static fn (string|BackedEnum $scope): string => $scope instanceof BackedEnum ? (string) $scope->value : $scope,
            $scopes,
        ));
    }

    public function handle(Request $request, Closure $next, string ...$scopes): Response
    {
        $user = $request->user();

        if (! $user instanceof AccessTokenBearer || ! $user->currentAccessToken() instanceof CurrentAccessToken) {
            throw OAuthServerException::invalidToken();
        }

        if (! $this->satisfies($user->currentAccessToken(), $scopes)) {
            throw OAuthServerException::insufficientScope();
        }

        return $next($request);
    }

    /** @param  list<string>  $scopes */
    protected function satisfies(CurrentAccessToken $token, array $scopes): bool
    {
        return array_all($scopes, fn (string $scope): bool => $token->can($scope));
    }
}
