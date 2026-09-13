<?php

declare(strict_types=1);

namespace Lock\Server\Tokens\Concerns;

use Illuminate\Database\Eloquent\Relations\HasMany;
use Lock\Server\Shared\Tokens\CurrentAccessToken;
use Lock\Server\Tokens\Models\AccessToken;

trait HasAccessTokens
{
    protected ?CurrentAccessToken $oidcAccessToken = null;

    /** @return HasMany<AccessToken, $this> */
    public function tokens(): HasMany
    {
        return $this->hasMany(AccessToken::class, 'user_id', $this->getAuthIdentifierName())->where('realm', AccessToken::currentRealm());
    }

    public function currentAccessToken(): ?CurrentAccessToken
    {
        return $this->oidcAccessToken;
    }

    public function withAccessToken(?CurrentAccessToken $accessToken): static
    {
        $this->oidcAccessToken = $accessToken;

        return $this;
    }

    public function tokenCan(string $scope): bool
    {
        return $this->oidcAccessToken !== null && $this->oidcAccessToken->can($scope);
    }
}
