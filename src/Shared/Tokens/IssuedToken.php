<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Tokens;

final readonly class IssuedToken
{
    /** @param string[] $scopes */
    public function __construct(
        public string $accessToken,
        public string $tokenType,
        public int $expiresIn,
        public string $audience,
        public array $scopes,
    ) {}

    public static function fromMinted(MintedAccessToken $token, string $audience): self
    {
        return new self(
            accessToken: $token->jwt,
            tokenType: 'Bearer',
            expiresIn: $token->lifetime(),
            audience: $audience,
            scopes: $token->scopes,
        );
    }
}
