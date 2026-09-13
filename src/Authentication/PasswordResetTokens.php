<?php

declare(strict_types=1);

namespace Lock\Server\Authentication;

use Illuminate\Auth\Passwords\TokenRepositoryInterface;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\CanResetPassword;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Str;
use Lock\Server\Authentication\Models\PasswordResetToken;
use Lock\Server\Shared\Realms\RealmResolver;
use LogicException;
use SensitiveParameter;

/**
 * The reset links a realm has handed out, one per user. A link only works in
 * the realm that sent it, and only for the realm's `tokens.password_reset`
 * lifetime; a request in one realm leaves another realm's pending link alone.
 */
final readonly class PasswordResetTokens implements TokenRepositoryInterface
{
    public const int THROTTLE_SECONDS = 60;

    public function __construct(private RealmResolver $realms) {}

    public function create(#[SensitiveParameter] CanResetPassword $user): string
    {
        $token = Str::random(64);

        $this->delete($user);

        PasswordResetToken::query()->create([
            'user_id' => $this->userId($user),
            'realm' => $this->realms->current()->identifier(),
            'token' => hash('sha256', $token),
            'created_at' => now(),
        ]);

        return $token;
    }

    public function exists(CanResetPassword $user, #[SensitiveParameter] $token): bool
    {
        $record = $this->forUser($user)->first();

        return $record instanceof PasswordResetToken
            && $record->created_at->isAfter(now()->subSeconds($this->lifetime()))
            && hash_equals($record->token, hash('sha256', (string) $token));
    }

    public function recentlyCreatedToken(CanResetPassword $user): bool
    {
        $record = $this->forUser($user)->first();

        return $record instanceof PasswordResetToken
            && $record->created_at->isAfter(now()->subSeconds(self::THROTTLE_SECONDS));
    }

    public function delete(CanResetPassword $user): void
    {
        $this->forUser($user)->delete();
    }

    public function deleteExpired(): void
    {
        PasswordResetToken::query()->inRealm()->where('created_at', '<', now()->subSeconds($this->lifetime()))->delete();
    }

    /**
     * @return Builder<PasswordResetToken>
     */
    private function forUser(CanResetPassword $user): Builder
    {
        return PasswordResetToken::query()->inRealm()->where('user_id', $this->userId($user));
    }

    private function userId(CanResetPassword $user): string
    {
        if (! $user instanceof Authenticatable) {
            throw new LogicException(sprintf('A password reset needs an authenticatable user; %s is not one.', $user::class));
        }

        return (string) $user->getAuthIdentifier();
    }

    private function lifetime(): int
    {
        return $this->realms->current()->tokens()->passwordResetLifetime;
    }
}
