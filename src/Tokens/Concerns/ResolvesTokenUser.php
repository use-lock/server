<?php

declare(strict_types=1);

namespace Lock\Server\Tokens\Concerns;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Auth;
use Lock\Server\Shared\Authentication\IdentityGuard;

trait ResolvesTokenUser
{
    private function resolveUser(?string $userIdentifier): ?Authenticatable
    {
        if ($userIdentifier === null) {
            return null;
        }

        $guard = IdentityGuard::name();
        $provider = Auth::createUserProvider(config("auth.guards.{$guard}.provider"));

        return $provider?->retrieveById($userIdentifier);
    }
}
