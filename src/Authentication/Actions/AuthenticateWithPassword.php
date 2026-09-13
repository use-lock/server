<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\Actions;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Lock\Server\Authentication\Events\LoginFailed;
use Lock\Server\Shared\Credentials\PasswordCredential;
use SensitiveParameter;

/**
 * Initial password tracking starts the rotation clock for previously untracked users.
 */
readonly class AuthenticateWithPassword
{
    public function __construct(
        protected PasswordCredential $passwords,
    ) {}

    public function __invoke(
        UserProvider $users,
        string $usernameField,
        string $username,
        #[SensitiveParameter] string $password,
    ): ?Authenticatable {
        $credentials = [$usernameField => strtolower($username), 'password' => $password];
        $user = $users->retrieveByCredentials($credentials);

        if ($user === null || ! $this->passwords->verify($user, $password)) {
            event(new LoginFailed(
                method: 'pwd',
                reason: 'invalid_credentials',
                userId: $user === null ? null : (string) $user->getAuthIdentifier(),
                username: $credentials[$usernameField],
            ));

            return null;
        }

        if (config('hashing.rehash_on_login', true)) {
            $users->rehashPasswordIfRequired($user, $credentials);
        }

        $this->passwords->track($user);

        return $user;
    }
}
