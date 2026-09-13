<?php

declare(strict_types=1);

namespace Lock\Server\Tokens;

final readonly class IdTokenRequest
{
    /**
     * @param  list<string>  $scopes
     * @param  list<string>  $amr
     * @param  array<string, mixed>  $idTokenClaims
     */
    public function __construct(
        public string $userId,
        public string $clientId,
        public array $scopes,
        public string $accessToken,
        public ?string $nonce = null,
        public ?int $authTime = null,
        public array $amr = [],
        public array $idTokenClaims = [],
        public ?string $sid = null,
    ) {}
}
