<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Clients;

use RuntimeException;

/**
 * An RFC 7591 registration error: `$error` is the wire error code
 * (`invalid_client_metadata`, `invalid_redirect_uri`), the message its
 * `error_description`.
 */
final class ClientRegistrationException extends RuntimeException
{
    public function __construct(public readonly string $error, string $description)
    {
        parent::__construct($description);
    }
}
