<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Tokens;

use DateTimeImmutable;

final readonly class MintedAccessToken
{
    /**
     * @param  list<string>  $scopes
     * @param  list<string>  $audience
     */
    public function __construct(
        public string $jwt,
        public string $jti,
        public ?string $userId,
        public string $clientId,
        public array $scopes,
        public array $audience,
        public DateTimeImmutable $issuedAt,
        public DateTimeImmutable $expiresAt,
    ) {}

    /** RFC 6749 §5.1 `expires_in`: the lifetime granted at issuance, not what is left of it by the time it is sent. */
    public function lifetime(): int
    {
        return $this->expiresAt->getTimestamp() - $this->issuedAt->getTimestamp();
    }

    public function toString(): string
    {
        return $this->jwt;
    }
}
