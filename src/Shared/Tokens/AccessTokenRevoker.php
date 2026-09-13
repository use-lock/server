<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Tokens;

interface AccessTokenRevoker
{
    /**
     * Revokes the access token with the given jti together with the refresh
     * token bound to it. Returns false when no live token carried that jti.
     */
    public function revoke(string $jti): bool;
}
