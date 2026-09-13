<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Realms\Settings;

final readonly class ClientSettings
{
    /**
     * @param  bool  $dynamicRegistration  RFC 7591 registration endpoint answers
     * @param  list<string>  $allowedRedirectSchemes  custom schemes accepted for registered redirect URIs
     * @param  list<string>  $allowedRedirectDomains  hosts accepted for http(s) redirect URIs; `*` for any
     * @param  list<string>  $defaultScopes  assigned to every new client and granted without being requested
     * @param  list<string>  $optionalScopes  assigned to every new client and granted on request; `*` for every catalog scope
     * @param  bool  $tokenExchange  RFC 8693 grant enabled
     * @param  string|null  $firstPartyClientId  the confidential client that mints session root tokens
     * @param  bool  $firstPartyTrusted  the first-party client skips the consent screen
     * @param  list<string>  $trustedClients  further clients that skip the consent screen
     */
    public function __construct(
        public bool $dynamicRegistration = false,
        public array $allowedRedirectSchemes = [],
        public array $allowedRedirectDomains = ['*'],
        public array $defaultScopes = [],
        public array $optionalScopes = ['*'],
        public bool $tokenExchange = true,
        public ?string $firstPartyClientId = null,
        public bool $firstPartyTrusted = false,
        public array $trustedClients = [],
    ) {}

    public static function fromConfig(): self
    {
        $clientId = config('oidc.clients.first_party.client_id');

        return new self(
            dynamicRegistration: (bool) config('oidc.clients.registration.enabled', false),
            allowedRedirectSchemes: array_values(array_map(strval(...), (array) config('oidc.clients.registration.allowed_redirect_schemes', []))),
            allowedRedirectDomains: array_values(array_map(strval(...), (array) config('oidc.clients.registration.allowed_redirect_domains', ['*']))),
            defaultScopes: array_values(array_map(strval(...), (array) config('oidc.clients.default_scopes', []))),
            optionalScopes: array_values(array_map(strval(...), (array) config('oidc.clients.optional_scopes', ['*']))),
            tokenExchange: (bool) config('oidc.clients.token_exchange', true),
            firstPartyClientId: is_string($clientId) && $clientId !== '' ? $clientId : null,
            firstPartyTrusted: (bool) config('oidc.clients.first_party.trusted', false),
            trustedClients: array_values(array_unique(array_map(strval(...), (array) config('oidc.clients.trusted', [])))),
        );
    }
}
