<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Realms;

use Illuminate\Support\Facades\Context;
use Illuminate\Support\Facades\URL;
use Lock\Server\Shared\Context\OidcContext;

final class CurrentRealm
{
    public const string ATTRIBUTE = 'oidc.realm';

    /**
     * Scoped queries, URLs and dispatched jobs use this realm inside the callback.
     * Restores the interrupted realm afterwards, including nested calls.
     */
    public static function runAs(string $realm, callable $callback): mixed
    {
        $attributes = request()->attributes;
        $previousAttribute = $attributes->get(self::ATTRIBUTE);
        $previousRealm = OidcContext::realm();
        $previousDefault = URL::getDefaultParameters()['realm'] ?? null;

        $attributes->set(self::ATTRIBUTE, $realm);
        OidcContext::rememberRealm($realm);
        URL::defaults(['realm' => $realm]);

        try {
            return $callback();
        } finally {
            $previousAttribute === null
                ? $attributes->remove(self::ATTRIBUTE)
                : $attributes->set(self::ATTRIBUTE, $previousAttribute);
            $previousRealm === null ? Context::forget(OidcContext::REALM) : OidcContext::rememberRealm($previousRealm);
            URL::defaults(['realm' => $previousDefault]);
        }
    }
}
