<?php

declare(strict_types=1);

namespace Lock\Server\Brokering;

use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use Lock\Server\Brokering\Models\SocialAccount;
use Lock\Server\Shared\Brokering\CreateUserFromSocialAccount;
use Lock\Server\Shared\Brokering\SocialAccountAlreadyLinkedException;
use Lock\Server\Shared\Brokering\SocialAccounts;
use Lock\Server\Shared\Brokering\SocialUser;
use Lock\Server\Shared\Realms\RealmResolver;
use RuntimeException;

class SocialAccountManager implements SocialAccounts
{
    public function __construct(
        private readonly Container $container,
        private readonly RealmResolver $realms,
    ) {}

    public function findAccount(string $provider, string $providerUserId): ?SocialAccount
    {
        return SocialAccount::query()
            ->inRealm()
            ->where('provider', $provider)
            ->where('provider_user_id', $providerUserId)
            ->first();
    }

    public function resolveUser(string $provider, SocialUser $socialUser, UserProvider $users): ?Authenticatable
    {
        $account = $this->findAccount($provider, $socialUser->id);

        if ($account instanceof SocialAccount) {
            $this->sync($account, $socialUser);

            return $users->retrieveById($account->user_id);
        }

        $brokering = $this->realms->current()->brokering();

        if ($brokering->linkByVerifiedEmail && $socialUser->emailVerified && $socialUser->email !== null) {
            $user = $users->retrieveByCredentials(['email' => $socialUser->email]);

            if ($user !== null) {
                $this->linkAccount($user, $provider, $socialUser);

                return $user;
            }
        }

        if ($brokering->autoProvision && $this->container->bound(CreateUserFromSocialAccount::class)) {
            return DB::transaction(function () use ($socialUser, $provider): Authenticatable {
                $user = $this->container->make(CreateUserFromSocialAccount::class)($socialUser, $provider);
                $this->linkAccount($user, $provider, $socialUser);

                return $user;
            });
        }

        return null;
    }

    public function link(Authenticatable $user, string $provider, SocialUser $socialUser): SocialAccount
    {
        if (! $user instanceof Model) {
            throw new RuntimeException('Social accounts require an Eloquent user model.');
        }

        $account = $this->findAccount($provider, $socialUser->id) ?? (new SocialAccount)->forceFill([
            'realm' => $this->realms->current()->identifier(),
            'provider' => $provider,
            'provider_user_id' => $socialUser->id,
        ]);

        $account->user_id = (string) $user->getAuthIdentifier();

        $this->sync($account, $socialUser);

        return $account;
    }

    public function linkAccount(Authenticatable $user, string $providerKey, SocialUser $socialUser): void
    {
        if (! $user instanceof Model) {
            throw new RuntimeException('Social accounts require an Eloquent user model.');
        }

        DB::transaction(function () use ($user, $providerKey, $socialUser): void {
            $account = SocialAccount::query()->lockForUpdate()->createOrFirst([
                'realm' => $this->realms->current()->identifier(),
                'provider' => $providerKey,
                'provider_user_id' => $socialUser->id,
            ], ['user_id' => (string) $user->getAuthIdentifier()]);

            if ($account->user_id !== (string) $user->getAuthIdentifier()) {
                throw new SocialAccountAlreadyLinkedException;
            }

            $this->sync($account, $socialUser);
        });
    }

    public function unlink(Authenticatable $user, string $accountId): void
    {
        $account = SocialAccount::query()->inRealm()->findOrFail($accountId);

        if ($account->user_id !== (string) $user->getAuthIdentifier()) {
            throw new AuthorizationException;
        }

        $account->delete();
    }

    private function sync(SocialAccount $account, SocialUser $socialUser): void
    {
        $account->fill([
            'email' => $socialUser->email ?? $account->email,
            // Apple only delivers the name on first consent; never null it out.
            'name' => $socialUser->name ?? $account->name,
            'nickname' => $socialUser->nickname ?? $account->nickname,
            'avatar' => $socialUser->avatar ?? $account->avatar,
            'access_token' => $socialUser->accessToken,
            'refresh_token' => $socialUser->refreshToken ?? $account->refresh_token,
            'token_expires_at' => $socialUser->expiresIn !== null ? now()->addSeconds($socialUser->expiresIn) : null,
            'raw' => $socialUser->raw,
        ]);

        $account->save();
    }
}
