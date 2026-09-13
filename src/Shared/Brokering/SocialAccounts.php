<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Brokering;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;

interface SocialAccounts
{
    public function resolveUser(string $provider, SocialUser $socialUser, UserProvider $users): ?Authenticatable;

    /** @throws SocialAccountAlreadyLinkedException */
    public function linkAccount(Authenticatable $user, string $providerKey, SocialUser $socialUser): void;

    public function unlink(Authenticatable $user, string $accountId): void;
}
