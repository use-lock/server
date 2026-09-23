<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Scopes;

/**
 * A scope id with one `{name}` placeholder, such as `organization:{organization}`,
 * stands for every scope that fills the placeholder with a value. The value
 * is a non-empty run of RFC 6749 §3.3 scope-token characters other than the
 * braces, so a template never matches itself.
 */
final readonly class ScopeTemplate
{
    private const string PLACEHOLDER = '/\{[A-Za-z0-9_]+\}/';

    private const string VALUE = '[\x21\x23-\x5B\x5D-\x7A\x7C\x7E]+';

    public static function isTemplate(string $id): bool
    {
        return preg_match_all(self::PLACEHOLDER, $id) === 1;
    }

    /** The value the scope fills the template's placeholder with, or null when it does not match. */
    public static function match(string $template, string $scope): ?string
    {
        if (! self::isTemplate($template)) {
            return null;
        }

        [$prefix, $suffix] = preg_split(self::PLACEHOLDER, $template, 2) ?: ['', ''];
        $pattern = '/^'.preg_quote($prefix, '/').'('.self::VALUE.')'.preg_quote($suffix, '/').'$/';

        return preg_match($pattern, $scope, $matches) === 1 ? $matches[1] : null;
    }

    public static function fill(string $template, string $value): string
    {
        return (string) preg_replace(self::PLACEHOLDER, str_replace(['\\', '$'], ['\\\\', '\\$'], $value), $template, 1);
    }
}
