<?php

declare(strict_types=1);

namespace Lock\Server\Authentication;

use Illuminate\Contracts\Auth\Authenticatable;

final readonly class PasswordResetResult
{
    /**
     * @param  string  $status  a password broker status key
     * @param  Authenticatable|null  $user  set only when the password was reset
     */
    public function __construct(
        public string $status,
        public ?Authenticatable $user,
    ) {}

    public function succeeded(): bool
    {
        return $this->user instanceof Authenticatable;
    }
}
