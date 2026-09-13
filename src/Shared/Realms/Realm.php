<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Realms;

use Lock\Server\Shared\Realms\Settings\AuthenticationSettings;
use Lock\Server\Shared\Realms\Settings\BrokeringSettings;
use Lock\Server\Shared\Realms\Settings\ClientSettings;
use Lock\Server\Shared\Realms\Settings\CredentialSettings;
use Lock\Server\Shared\Realms\Settings\KeySettings;
use Lock\Server\Shared\Realms\Settings\LoginSettings;
use Lock\Server\Shared\Realms\Settings\ResourceSettings;
use Lock\Server\Shared\Realms\Settings\ScopeSettings;
use Lock\Server\Shared\Realms\Settings\SessionSettings;
use Lock\Server\Shared\Realms\Settings\TokenSettings;

/**
 * Host applications implement this contract for tenant settings and expose it
 * through RealmRepository; branding and administration remain host-owned.
 */
interface Realm
{
    public function identifier(): string;

    /**
     * The host the realm is served from in `domain` routing, without scheme or
     * port — the issuer's host, and where every URL to its pages points. Null
     * where realms share the application's host.
     */
    public function host(): ?string;

    public function tokens(): TokenSettings;

    public function resources(): ResourceSettings;

    public function sessions(): SessionSettings;

    public function login(): LoginSettings;

    public function authentication(): AuthenticationSettings;

    public function credentials(): CredentialSettings;

    public function brokering(): BrokeringSettings;

    public function scopes(): ScopeSettings;

    public function clients(): ClientSettings;

    public function keys(): KeySettings;
}
