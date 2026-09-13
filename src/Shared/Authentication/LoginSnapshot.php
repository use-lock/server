<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Authentication;

final readonly class LoginSnapshot
{
    /**
     * @param  list<string>  $amr
     * @param  array<string, mixed>  $idTokenClaims
     * @param  array<string, mixed>  $accessTokenClaims
     */
    public function __construct(
        public array $amr,
        public array $idTokenClaims,
        public array $accessTokenClaims,
    ) {}
}
