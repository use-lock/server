<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\Contracts;

use Illuminate\Contracts\Auth\CanResetPassword;

/**
 * Bind an implementation to enable the password reset flow. It receives the
 * validated reset request and is responsible for persisting the new password.
 */
interface ResetUserPassword
{
    /**
     * @param  array<string, mixed>  $input
     */
    public function __invoke(CanResetPassword $user, array $input): void;
}
