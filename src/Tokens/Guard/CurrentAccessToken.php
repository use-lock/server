<?php

declare(strict_types=1);

namespace Lock\Server\Tokens\Guard;

use Lock\Server\Shared\Clients\Clients;
use Lock\Server\Tokens\Models\AccessToken;
use Lock\Server\Tokens\TokenRevoker;

final class CurrentAccessToken implements \Lock\Server\Shared\Tokens\CurrentAccessToken
{
    private ?string $clientId = null;

    public function __construct(private readonly AccessToken $token) {}

    public function userId(): ?string
    {
        return $this->token->user_id;
    }

    public function id(): string
    {
        return $this->token->getKey();
    }

    /** @return list<string> */
    public function scopes(): array
    {
        return array_values($this->token->scopes ?? []);
    }

    /** The wire client_id, not the primary key. */
    public function clientId(): ?string
    {
        $key = $this->token->getAttribute('client_id');

        if (! is_string($key) || $key === '') {
            return null;
        }

        return $this->clientId ??= app(Clients::class)->findByKey($key, $this->token->realm)?->clientId;
    }

    public function can(string $scope): bool
    {
        return in_array('*', $this->scopes(), true) || in_array($scope, $this->scopes(), true);
    }

    public function revoke(): bool
    {
        return app(TokenRevoker::class)->revoke($this->id());
    }
}
