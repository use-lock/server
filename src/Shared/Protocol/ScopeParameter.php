<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Protocol;

/**
 * RFC 6749 §3.3: a space-delimited, case-sensitive list; absent or blank means none requested.
 */
final class ScopeParameter
{
    /** @return list<string>|null null when the parameter is absent */
    public static function parse(mixed $value): ?array
    {
        if ($value === null) {
            return null;
        }

        if (! is_string($value)) {
            return [];
        }

        return array_values(array_unique(array_filter(explode(' ', trim($value)), fn (string $scope): bool => $scope !== '')));
    }
}
