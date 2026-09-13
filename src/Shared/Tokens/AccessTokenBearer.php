<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Tokens;

interface AccessTokenBearer
{
    public function currentAccessToken(): ?CurrentAccessToken;

    public function withAccessToken(?CurrentAccessToken $accessToken): static;
}
