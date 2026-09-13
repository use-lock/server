<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Clients;

/**
 * RFC 7591 §2 / OIDC Registration §2: how a client authenticates at the
 * token, introspection and revocation endpoints. Enforced exactly: a client
 * registered for one method is refused when it presents another.
 */
enum TokenEndpointAuthMethod: string
{
    case ClientSecretBasic = 'client_secret_basic';
    case ClientSecretPost = 'client_secret_post';
    case None = 'none';

    public function requiresSecret(): bool
    {
        return $this !== self::None;
    }
}
