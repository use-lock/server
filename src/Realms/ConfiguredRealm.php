<?php

declare(strict_types=1);

namespace Lock\Server\Realms;

use Lock\Server\Shared\Realms\Realm;
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
 * A realm whose settings are the `config('oidc.*')` values. The default for
 * single-realm deployments and the fallback for every realm id when no
 * RealmRepository is bound; settings are read on every call so a config
 * change during a request (or a test) is seen immediately.
 */
final readonly class ConfiguredRealm implements Realm
{
    public function __construct(private string $id) {}

    public function identifier(): string
    {
        return $this->id;
    }

    public function host(): ?string
    {
        $host = array_search($this->id, (array) config('oidc.routes.domains', []), true);

        return is_string($host) ? $host : null;
    }

    public function tokens(): TokenSettings
    {
        return TokenSettings::fromConfig();
    }

    public function resources(): ResourceSettings
    {
        return ResourceSettings::fromConfig();
    }

    public function sessions(): SessionSettings
    {
        return SessionSettings::fromConfig();
    }

    public function login(): LoginSettings
    {
        return LoginSettings::fromConfig();
    }

    public function authentication(): AuthenticationSettings
    {
        return AuthenticationSettings::fromConfig();
    }

    public function credentials(): CredentialSettings
    {
        return CredentialSettings::fromConfig();
    }

    public function brokering(): BrokeringSettings
    {
        return BrokeringSettings::fromConfig();
    }

    public function scopes(): ScopeSettings
    {
        return ScopeSettings::fromConfig();
    }

    public function clients(): ClientSettings
    {
        return ClientSettings::fromConfig();
    }

    public function keys(): KeySettings
    {
        return KeySettings::fromConfig();
    }
}
