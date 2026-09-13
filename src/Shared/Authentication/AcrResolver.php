<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Authentication;

/**
 * Maps the authentication methods of a login (`amr`) to the Authentication
 * Context Class Reference the provider reports for it (OIDC Core §2), and
 * enumerates the values advertised as `acr_values_supported` (OIDC
 * Discovery §3).
 */
interface AcrResolver
{
    /** @param  list<string>  $amr */
    public function fromAmr(array $amr): ?string;

    /** @return list<string> */
    public function supported(): array;
}
