<?php

declare(strict_types=1);

namespace Lock\Server\Tokens\Guard;

use BadMethodCallException;
use Illuminate\Contracts\Auth\Authenticatable;
use Lock\Server\Shared\Authentication\RealmUser;
use Lock\Server\Shared\Clients\Client;
use Lock\Server\Shared\Tokens\AccessTokenBearer;
use Lock\Server\Shared\Tokens\CurrentAccessToken;

/**
 * Userless tokens authorize through scopes and audiences, without user roles.
 * $request->user() instanceof ClientPrincipal distinguishes machine callers
 * from the host application's RealmUser users.
 */
final class ClientPrincipal implements AccessTokenBearer, Authenticatable
{
    private ?CurrentAccessToken $accessToken = null;

    public function __construct(public readonly Client $client) {}

    /** The wire client_id, which the token carries as both `client_id` and `sub`. */
    public function clientId(): string
    {
        return $this->client->clientId;
    }

    public function currentAccessToken(): ?CurrentAccessToken
    {
        return $this->accessToken;
    }

    public function withAccessToken(?CurrentAccessToken $accessToken): static
    {
        $this->accessToken = $accessToken;

        return $this;
    }

    public function tokenCan(string $scope): bool
    {
        return $this->accessToken?->can($scope) ?? false;
    }

    public function getAuthIdentifierName(): string
    {
        return 'client_id';
    }

    public function getAuthIdentifier(): string
    {
        return $this->clientId();
    }

    public function getAuthPasswordName(): string
    {
        throw $this->hasNoCredentials();
    }

    public function getAuthPassword(): string
    {
        throw $this->hasNoCredentials();
    }

    public function getRememberToken(): ?string
    {
        return null;
    }

    public function setRememberToken(mixed $value): void {}

    public function getRememberTokenName(): string
    {
        return '';
    }

    /**
     * A client principal exists only for the lifetime of a request already authenticated by its
     * bearer token; the credential members of Authenticatable have no counterpart on it, and
     * reaching for one means a password or session flow was handed a machine caller.
     */
    private function hasNoCredentials(): BadMethodCallException
    {
        return new BadMethodCallException('A client principal authenticates by access token and has no password.');
    }
}
