<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Brokering;

final readonly class SocialUser
{
    /**
     * @param  array<string, mixed>  $raw
     */
    public function __construct(
        public string $id,
        public ?string $email,
        public bool $emailVerified,
        public ?string $name,
        public ?string $nickname,
        public ?string $avatar,
        public array $raw = [],
        public ?string $accessToken = null,
        public ?string $refreshToken = null,
        public ?int $expiresIn = null,
        public ?string $idToken = null,
    ) {}
}
