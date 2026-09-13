<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\Actions;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Session\Session;
use Lock\Server\Authentication\PasswordConfirmation;
use Lock\Server\Shared\Credentials\PasswordCredential;
use SensitiveParameter;

readonly class ConfirmPassword
{
    public function __construct(private PasswordCredential $passwords) {}

    public function __invoke(Authenticatable $user, #[SensitiveParameter] string $password, Session $session): bool
    {
        if (! $this->passwords->verify($user, $password)) {
            return false;
        }

        PasswordConfirmation::confirm($session);

        return true;
    }
}
