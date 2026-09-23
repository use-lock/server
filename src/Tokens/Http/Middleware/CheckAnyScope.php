<?php

declare(strict_types=1);

namespace Lock\Server\Tokens\Http\Middleware;

use Lock\Server\Tokens\Guard\CurrentAccessToken;

/**
 * Passes a token that carries at least one of the listed scopes.
 */
class CheckAnyScope extends CheckScopes
{
    /** @param  list<string>  $scopes */
    #[\Override]
    protected function satisfies(CurrentAccessToken $token, array $scopes): bool
    {
        return array_any($scopes, fn (string $scope): bool => $token->can($scope));
    }
}
