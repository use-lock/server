<?php

declare(strict_types=1);

namespace Lock\Server\Protocol\Exceptions;

use Illuminate\Auth\Access\AuthorizationException;

final class InvalidConsentTokenException extends AuthorizationException
{
    public static function different(): static
    {
        return new self('The provided auth token for the request is different from the session auth token.');
    }
}
