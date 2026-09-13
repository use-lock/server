<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\Actions;

use Illuminate\Auth\Events\Registered;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Container\Container;
use Illuminate\Support\Facades\DB;
use Lock\Server\Authentication\Contracts\CreateUser;
use Lock\Server\Authentication\Events\UserRegistered;
use Lock\Server\Shared\Credentials\PasswordCredential;
use Lock\Server\Shared\Realms\RealmResolver;

/**
 * CreateUser owns validation beyond the realm password policy.
 */
readonly class RegisterUser
{
    public function __construct(
        protected Container $container,
        protected PasswordCredential $passwords,
        protected RealmResolver $realms,
    ) {}

    public function enabled(): bool
    {
        return $this->container->bound(CreateUser::class);
    }

    /**
     * @param  array<string, mixed>  $input
     */
    public function __invoke(array $input): Authenticatable
    {
        if (isset($input['email']) && is_string($input['email'])) {
            $input['email'] = strtolower($input['email']);
        }

        if (is_string($input['password'] ?? null) && $input['password'] !== '') {
            $this->passwords->validate(null, $input['password']);
        }

        $user = DB::transaction(function () use ($input): Authenticatable {
            $user = $this->container->make(CreateUser::class)($input);
            $this->passwords->record($user);

            return $user;
        });

        DB::afterCommit(fn () => event(new Registered($user)));

        event(new UserRegistered((string) $user->getAuthIdentifier(), $this->realms->current()->identifier()));

        return $user;
    }
}
