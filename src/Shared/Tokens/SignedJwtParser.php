<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Tokens;

use Lcobucci\JWT\Token\Plain;

/**
 * Returns null for malformed JWTs, invalid realm signatures or a foreign issuer.
 * Other claims are not validated here.
 */
interface SignedJwtParser
{
    public function parse(string $jwt): ?Plain;
}
