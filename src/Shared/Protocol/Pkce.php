<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Protocol;

/**
 * RFC 7636. Only S256 is supported: OAuth 2.1 §4.1.1 drops `plain`.
 */
final class Pkce
{
    public const string METHOD = 'S256';

    /** RFC 7636 §4.1 / §4.2: 43..128 unreserved characters. */
    private const string SYNTAX = '/^[A-Za-z0-9\-._~]{43,128}$/';

    public static function isWellFormed(string $value): bool
    {
        return preg_match(self::SYNTAX, $value) === 1;
    }

    public static function verify(string $verifier, string $challenge): bool
    {
        return hash_equals($challenge, self::challenge($verifier));
    }

    public static function challenge(string $verifier): string
    {
        return sodium_bin2base64(hash('sha256', $verifier, true), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    }
}
