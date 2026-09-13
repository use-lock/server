<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Protocol;

final class ProtocolClaims
{
    /** @var list<string> */
    public const array RESERVED = [
        'iss', 'sub', 'aud', 'exp', 'iat', 'nbf', 'jti',
        'nonce', 'at_hash', 'c_hash', 'auth_time', 'azp', 'acr', 'amr', 'sid',
    ];

    /** @var list<string> */
    private const array ACCESS_TOKEN_RESERVED = ['client_id', 'scope', 'scopes', 'cnf', 'act'];

    public static function isReserved(string $name): bool
    {
        return in_array($name, self::RESERVED, true);
    }

    public static function isAccessTokenReserved(string $name): bool
    {
        return self::isReserved($name) || in_array($name, self::ACCESS_TOKEN_RESERVED, true);
    }
}
