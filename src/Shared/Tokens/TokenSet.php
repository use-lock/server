<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Tokens;

final readonly class TokenSet
{
    /** @param array<string, mixed> $extra */
    public function __construct(
        public MintedAccessToken $accessToken,
        public ?string $refreshToken = null,
        public ?string $idToken = null,
        public array $extra = [],
    ) {}
}
