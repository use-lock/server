<?php

declare(strict_types=1);

namespace Lock\Server\Realms;

use Lock\Server\Realms\Enums\RealmRouting;
use Lock\Server\Shared\Realms\IssuerResolver;
use Lock\Server\Shared\Realms\RealmResolver;

/**
 * The configured issuer supplies the origin. Below `/realms/{realm}` every
 * realm is its own OpenID Provider with its own issuer; a single-realm
 * deployment is the origin itself. In `domain` routing the realm's host
 * replaces the configured one, which keeps its scheme and port — the issuer
 * is the same whichever host a request, a queued job or a console command
 * happens to run on.
 *
 * `oidc.issuer` is an origin without a path. Routes are registered at the
 * application root, so a path in the issuer would only be carried into the
 * discovery document and name endpoints that answer 404.
 */
final readonly class RealmIssuerResolver implements IssuerResolver
{
    public function __construct(private RealmResolver $realms) {}

    public function url(): string
    {
        $routing = RealmRouting::configured();
        $realm = $this->realms->current();
        $host = $realm->host();

        if ($routing === RealmRouting::Domain && $host !== null) {
            return $this->originOf($host);
        }

        return $this->configuredOrigin().$routing->issuerPath($realm->identifier());
    }

    private function originOf(string $host): string
    {
        $configured = $this->configuredOrigin();
        $port = parse_url($configured, PHP_URL_PORT);

        return (parse_url($configured, PHP_URL_SCHEME) ?: 'https').'://'.$host.($port !== null ? ':'.$port : '');
    }

    private function configuredOrigin(): string
    {
        return rtrim((string) (config('oidc.issuer') ?: config('app.url')), '/');
    }
}
