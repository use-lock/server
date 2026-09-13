<?php

declare(strict_types=1);

namespace Lock\Server\Brokering;

final readonly class TokenResponse
{
    public function __construct(
        public ?string $accessToken,
        public ?string $refreshToken,
        public ?int $expiresIn,
        public ?string $idToken,
    ) {}

    /**
     * @param  array<string, mixed>  $payload
     */
    public static function fromArray(array $payload): self
    {
        return new self(
            accessToken: is_string($payload['access_token'] ?? null) ? $payload['access_token'] : null,
            refreshToken: is_string($payload['refresh_token'] ?? null) ? $payload['refresh_token'] : null,
            expiresIn: is_numeric($payload['expires_in'] ?? null) ? (int) $payload['expires_in'] : null,
            idToken: is_string($payload['id_token'] ?? null) ? $payload['id_token'] : null,
        );
    }
}
