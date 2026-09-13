<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Clients;

use SensitiveParameter;

interface ClientProvisioner
{
    /**
     * @param  string[]  $redirectUris
     * @param  string[]  $postLogoutRedirectUris
     * @param  string[]  $allowedExchangeAudiences
     * @param  string[]|null  $defaultScopes
     * @param  string[]|null  $optionalScopes
     */
    public function provision(
        string $name,
        array $redirectUris,
        array $postLogoutRedirectUris = [],
        array $allowedExchangeAudiences = [],
        ?string $adoptClientId = null,
        bool $rotateSecret = false,
        #[SensitiveParameter] ?string $existingClientSecret = null,
        ?array $defaultScopes = null,
        ?array $optionalScopes = null,
    ): ProvisionedClient;

    public function rollback(ProvisionedClient $result): void;
}
