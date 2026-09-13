<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\Actions;

use Illuminate\Auth\Events\PasswordReset as PasswordWasReset;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\CanResetPassword;
use Illuminate\Contracts\Auth\PasswordBroker;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Password;
use Lock\Server\Authentication\Events\PasswordReset;
use Lock\Server\Authentication\PasswordResetResult;
use Lock\Server\Shared\Realms\RealmResolver;
use RuntimeException;

/**
 * Password replacement and reset-token consumption commit together.
 */
readonly class ResetPassword
{
    public function __construct(
        protected UpdatePassword $passwords,
        protected PasswordBroker $broker,
        protected RealmResolver $realms,
    ) {}

    /**
     * @param  array<string, mixed>  $input  the full reset request (token, email, password, password_confirmation, …)
     */
    public function __invoke(array $input): PasswordResetResult
    {
        return DB::transaction(function () use ($input): PasswordResetResult {
            $resetUser = null;

            $status = $this->broker->reset(
                array_intersect_key($input, array_flip(['email', 'password', 'password_confirmation', 'token'])),
                function (CanResetPassword $user) use ($input, &$resetUser): void {
                    if (! $user instanceof Authenticatable) {
                        throw new RuntimeException('The reset password user must be authenticatable.');
                    }

                    $this->passwords->replace($user, $input);
                    DB::afterCommit(fn () => event(new PasswordWasReset($user)));

                    $resetUser = $user;
                },
            );

            if ($status === Password::PASSWORD_RESET && $resetUser instanceof Authenticatable) {
                event(new PasswordReset((string) $resetUser->getAuthIdentifier(), $this->realms->current()->identifier()));

                return new PasswordResetResult($status, $resetUser);
            }

            return new PasswordResetResult(is_string($status) ? $status : Password::INVALID_TOKEN, null);
        });
    }
}
