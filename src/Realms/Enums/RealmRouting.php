<?php

declare(strict_types=1);

namespace Lock\Server\Realms\Enums;

use ValueError;

/**
 * Where realms appear in URLs. `single` serves the configured realm from the
 * application root, so the issuer is the bare origin; `path` serves every
 * realm below `/realms/{realm}` and gives each its own issuer; `domain`
 * serves every realm from its own host, so each is its own origin and every
 * endpoint keeps the path it has in `single`.
 */
enum RealmRouting: string
{
    case Single = 'single';
    case Path = 'path';
    case Domain = 'domain';

    public const string SEGMENT = 'realms';

    public static function configured(): self
    {
        $mode = config('oidc.routes.realms', self::Single->value);

        return self::tryFrom(is_string($mode) ? $mode : '')
            ?? throw new ValueError('oidc.routes.realms must be "single", "path" or "domain".');
    }

    /** The prefix the realm's routes sit below; the well-known metadata routes carry the realm behind the well-known segment instead. */
    public function prefix(): string
    {
        return $this === self::Path ? self::SEGMENT.'/{realm}' : '';
    }

    /**
     * RFC 8414 §3.1 and RFC 9728 §3.1 insert the well-known segment ahead of
     * the issuer's path, so the realm follows the well-known segment there.
     */
    public function wellKnownSuffix(): string
    {
        return $this === self::Path ? self::SEGMENT.'/{realm}/' : '';
    }

    /** A route path pattern for the given package path, e.g. for middleware exceptions. */
    public function pattern(string $path): string
    {
        return $this === self::Path ? self::SEGMENT.'/*/'.$path : $path;
    }

    /** The URL path a realm's routes live below; the session cookie path in `path` mode. */
    public function path(string $realm): string
    {
        return $this === self::Path ? '/'.self::SEGMENT.'/'.$realm : '/';
    }

    public function issuerPath(string $realm): string
    {
        return $this === self::Path ? '/'.self::SEGMENT.'/'.$realm : '';
    }
}
