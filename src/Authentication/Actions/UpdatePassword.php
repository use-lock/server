<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\Actions;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\CanResetPassword;
use Illuminate\Contracts\Container\Container;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Lock\Server\Authentication\Contracts\ResetUserPassword;
use Lock\Server\Authentication\Events\PasswordChanged;
use Lock\Server\Shared\Credentials\PasswordCredential;
use Lock\Server\Shared\Realms\RealmResolver;

/**
 * ResetUserPassword owns persistence; remember-token rotation invalidates other browsers.
 */
readonly class UpdatePassword
{
    public function __construct(
        protected Container $container,
        protected PasswordCredential $passwords,
        protected RealmResolver $realms,
    ) {}

    public function enabled(): bool
    {
        return $this->container->bound(ResetUserPassword::class);
    }

    /**
     * @param  array<string, mixed>  $input
     */
    public function __invoke(Authenticatable&CanResetPassword $user, array $input): void
    {
        $this->replace($user, $input);

        event(new PasswordChanged((string) $user->getAuthIdentifier(), $this->realms->current()->identifier()));
    }

    /** @param array<string, mixed> $input */
    public function replace(Authenticatable&CanResetPassword $user, array $input): void
    {
        $this->passwords->validate($user, is_string($input['password'] ?? null) ? $input['password'] : '');

        DB::transaction(function () use ($user, $input): void {
            $this->container->make(ResetUserPassword::class)($user, $input);

            $user->setRememberToken(Str::random(60));

            if (method_exists($user, 'save')) {
                $user->save();
            }

            $this->passwords->record($user);
        });
    }
}
