<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\Actions;

use Illuminate\Contracts\Auth\PasswordBroker;

/**
 * Uses the current realm; use CurrentRealm::runAs() for another realm.
 */
readonly class SendPasswordResetLink
{
    public function __construct(private PasswordBroker $broker) {}

    public function __invoke(string $email): string
    {
        return $this->broker->sendResetLink(['email' => strtolower($email)]);
    }
}
