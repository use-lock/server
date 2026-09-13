<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Context;

use Illuminate\Support\Facades\Context;

/**
 * Laravel propagates this context to queued jobs and log entries, preserving
 * the originating realm on workers.
 */
final class OidcContext
{
    public const string REALM = 'oidc.realm';

    public const string CLIENT = 'oidc.client_id';

    public static function rememberRealm(string $realm): void
    {
        Context::add(self::REALM, $realm);
    }

    public static function realm(): ?string
    {
        $realm = Context::get(self::REALM);

        return is_string($realm) && $realm !== '' ? $realm : null;
    }

    public static function rememberClient(string $clientId): void
    {
        Context::add(self::CLIENT, $clientId);
    }

    public static function client(): ?string
    {
        $clientId = Context::get(self::CLIENT);

        return is_string($clientId) && $clientId !== '' ? $clientId : null;
    }
}
