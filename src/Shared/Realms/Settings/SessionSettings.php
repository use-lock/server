<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Realms\Settings;

use DateInterval;

final readonly class SessionSettings
{
    /**
     * @param  int  $absoluteLifetime  seconds an SSO session may live regardless of activity
     * @param  int  $tokenTtl  seconds the first-party session root token lives
     * @param  int  $tokenRefreshSkew  seconds before expiry at which the root token is re-minted
     * @param  list<string>|null  $tokenScopes  scopes of the root token; null grants every visible scope
     */
    public function __construct(
        public int $absoluteLifetime = 2592000,
        public int $tokenTtl = 3600,
        public int $tokenRefreshSkew = 60,
        public ?array $tokenScopes = null,
        public ?string $cookieName = null,
    ) {}

    public static function fromConfig(): self
    {
        $scopes = config('oidc.session.token.scopes');
        $cookieName = config('oidc.session.cookie_name');

        return new self(
            absoluteLifetime: (int) config('oidc.session.absolute_lifetime', 2592000),
            tokenTtl: (int) config('oidc.session.token.ttl', 3600),
            tokenRefreshSkew: (int) config('oidc.session.token.refresh_skew', 60),
            tokenScopes: is_array($scopes) ? array_values($scopes) : null,
            cookieName: is_string($cookieName) && $cookieName !== '' ? $cookieName : null,
        );
    }

    public function absolute(): DateInterval
    {
        return new DateInterval('PT'.max($this->absoluteLifetime, 1).'S');
    }

    public function token(): DateInterval
    {
        return new DateInterval('PT'.max($this->tokenTtl, 1).'S');
    }
}
