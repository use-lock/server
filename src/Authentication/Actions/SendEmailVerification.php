<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\Actions;

use Illuminate\Contracts\Auth\MustVerifyEmail;

class SendEmailVerification
{
    public function __invoke(MustVerifyEmail $user): bool
    {
        if ($user->hasVerifiedEmail()) {
            return false;
        }

        $user->sendEmailVerificationNotification();

        return true;
    }
}
