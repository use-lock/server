<?php

declare(strict_types=1);

namespace Lock\Server\Scopes\Claims;

use Illuminate\Database\Eloquent\Model;
use Lock\Server\Shared\Scopes\ClaimSet;
use Lock\Server\Shared\Scopes\ClaimsRequest;
use Lock\Server\Shared\Scopes\ClaimsResolver;

/**
 * Maps the `profile` and `email` scopes onto same-named user attributes:
 * name, locale from `locale`, zoneinfo from `timezone`, updated_at, and
 * email with email_verified from `email_verified_at`. An attribute the
 * user lacks omits its claim. Anything beyond that, the OIDC `phone` and
 * `address` scopes included, is an app-bound ClaimsResolver.
 */
class StandardClaimsResolver implements ClaimsResolver
{
    /** @return array<string, mixed> */
    public function resolve(ClaimsRequest $request): array
    {
        return $this->claimSet($request)->forScopes($request->scopes);
    }

    protected function claimSet(ClaimsRequest $request): ClaimSet
    {
        $user = $request->user;

        if (! $user instanceof Model) {
            return new ClaimSet;
        }

        return new ClaimSet([
            'profile' => [
                'name' => $this->attribute($user, 'name'),
                'locale' => $this->attribute($user, 'locale'),
                'zoneinfo' => $this->attribute($user, 'timezone'),
                'updated_at' => $this->attribute($user, 'updated_at')?->getTimestamp(),
            ],
            'email' => [
                'email' => $this->attribute($user, 'email'),
                'email_verified' => $this->attribute($user, 'email') !== null
                    ? $this->attribute($user, 'email_verified_at') !== null
                    : null,
            ],
        ]);
    }

    /**
     * Reads through the model so casts and accessors apply, but never a column
     * the model does not carry: a strict model would throw on the lookup.
     */
    private function attribute(Model $user, string $key): mixed
    {
        return $user->hasAttribute($key) ? $user->getAttribute($key) : null;
    }
}
