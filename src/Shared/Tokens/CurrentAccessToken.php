<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Tokens;

interface CurrentAccessToken
{
    public function id(): string;

    public function userId(): ?string;

    public function clientId(): ?string;

    /** @return list<string> */
    public function scopes(): array;

    public function can(string $scope): bool;

    public function revoke(): bool;
}
