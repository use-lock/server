<?php

declare(strict_types=1);

namespace Lock\Server\Tokens;

use Lock\Server\Tokens\Models\AccessToken;

final readonly class DirectAccessTokenResult
{
    public function __construct(
        public string $accessToken,
        public AccessToken $token,
    ) {}
}
