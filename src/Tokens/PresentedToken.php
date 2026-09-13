<?php

declare(strict_types=1);

namespace Lock\Server\Tokens;

use Lcobucci\JWT\Token\Plain;
use Lock\Server\Tokens\Models\AccessToken;
use Lock\Server\Tokens\Models\RefreshToken;

/**
 * RFC 7662 §2.1 / RFC 7009 §2.1: a presented refresh token carries the
 * access-token record it was issued alongside; an access token carries its own.
 */
final readonly class PresentedToken
{
    private function __construct(
        public AccessToken $accessToken,
        public ?Plain $jwt,
        public ?RefreshToken $refreshToken,
    ) {}

    public static function accessToken(Plain $jwt, AccessToken $accessToken): self
    {
        return new self($accessToken, $jwt, null);
    }

    public static function refreshToken(RefreshToken $refreshToken, AccessToken $accessToken): self
    {
        return new self($accessToken, null, $refreshToken);
    }

    public function isRefreshToken(): bool
    {
        return $this->refreshToken instanceof RefreshToken;
    }
}
