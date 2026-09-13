<?php

declare(strict_types=1);

namespace Lock\Server\Protocol;

use Lock\Server\Shared\Realms\IssuerResolver;
use Lock\Server\Shared\Realms\RealmResolver;

/**
 * Endpoint paths already carry the realm, so use the issuer's origin.
 * Building from the issuer keeps forwarded hosts out of metadata (RFC 8414 §3)
 * and bearer challenges (RFC 9728 §5.1).
 */
final readonly class EndpointUrl
{
    public function __construct(
        private IssuerResolver $issuer,
        private RealmResolver $realms,
    ) {}

    public function of(string $routeName): string
    {
        $path = parse_url(route($routeName, ['realm' => $this->realms->current()->identifier()]), PHP_URL_PATH);

        return $this->origin().($path ?? '');
    }

    private function origin(): string
    {
        $issuer = rtrim($this->issuer->url(), '/');
        $parts = parse_url($issuer);

        if (! isset($parts['scheme'], $parts['host'])) {
            return $issuer;
        }

        $port = isset($parts['port']) ? ':'.$parts['port'] : '';

        return $parts['scheme'].'://'.$parts['host'].$port;
    }
}
