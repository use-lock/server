<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Realms\Settings;

final readonly class ScopeSettings
{
    /**
     * @param  array<string, string>|class-string  $catalog  the API scopes on top of the OIDC standard scopes, or a ScopeCatalog implementation resolved from the container
     * @param  list<string>  $claimsSupported  advertised in the discovery document
     */
    public function __construct(
        public array|string $catalog = [],
        public array $claimsSupported = [],
    ) {}

    public static function fromConfig(): self
    {
        $catalog = config('oidc.scopes', []);

        return new self(
            catalog: is_string($catalog) || is_array($catalog) ? $catalog : [],
            claimsSupported: array_values((array) config('oidc.claims_supported', [])),
        );
    }
}
