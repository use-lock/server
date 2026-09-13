<?php

declare(strict_types=1);

namespace Lock\Server\Protocol\Http;

final class RedirectUri
{
    /**
     * OAuth 2.1 §4.1.3: registered and requested URIs must match character by
     * character; RFC 8252 §7.3 exempts the port of a loopback redirect.
     *
     * @param  list<string>  $registered
     */
    public static function matches(string $requested, array $registered): bool
    {
        return array_any($registered, fn (string $candidate): bool => hash_equals($candidate, $requested) || self::loopbackMatches($requested, $candidate));
    }

    private static function loopbackMatches(string $requested, string $registered): bool
    {
        $requestedParts = parse_url($requested);
        $registeredParts = parse_url($registered);

        if ($requestedParts === false || $registeredParts === false) {
            return false;
        }

        $host = $requestedParts['host'] ?? null;

        if (($requestedParts['scheme'] ?? null) !== 'http' || ! in_array($host, ['127.0.0.1', '[::1]'], true)) {
            return false;
        }

        unset($requestedParts['port'], $registeredParts['port']);

        return $requestedParts === $registeredParts;
    }
}
