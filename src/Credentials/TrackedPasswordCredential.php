<?php

declare(strict_types=1);

namespace Lock\Server\Credentials;

use Carbon\CarbonInterface;
use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Validator;
use Lock\Server\Credentials\Models\PasswordHistory;
use Lock\Server\Shared\Credentials\PasswordCredential;
use Lock\Server\Shared\Realms\RealmResolver;
use Lock\Server\Shared\Realms\Settings\PasswordPolicy;
use SensitiveParameter;

/**
 * History starts on first observed login or change; untracked users have no rotation clock.
 */
final readonly class TrackedPasswordCredential implements PasswordCredential
{
    public function __construct(
        private Hasher $hasher,
        private RealmResolver $realms,
    ) {}

    public function verify(Authenticatable $user, #[SensitiveParameter] string $password): bool
    {
        $hash = $user->getAuthPassword();

        return $hash !== '' && $this->hasher->check($password, $hash);
    }

    public function validate(?Authenticatable $user, #[SensitiveParameter] string $password): void
    {
        $policy = $this->policy();
        $rules = [$policy->rule()];

        if ($user instanceof Authenticatable && $policy->history > 0) {
            $rules[] = function (string $attribute, mixed $value, Closure $fail) use ($user, $policy): void {
                if (is_string($value) && $this->wasUsedRecently($user, $value, $policy->history)) {
                    $fail(__('The password was used recently. Choose one you have not used before.'));
                }
            };
        }

        Validator::make(['password' => $password], ['password' => $rules])->validate();
    }

    public function record(Authenticatable $user): void
    {
        if (! $user instanceof Model) {
            return;
        }

        $hash = $user->getAuthPassword();

        if ($hash === '' || $this->latest($user)?->hash === $hash) {
            return;
        }

        $user->hasMany(PasswordHistory::class, 'user_id')->create([
            'hash' => $hash,
            'created_at' => now(),
        ]);

        $this->prune($user);
    }

    public function track(Authenticatable $user): void
    {
        if ($user instanceof Model && ! $this->latest($user) instanceof PasswordHistory) {
            $this->record($user);
        }
    }

    public function changedAt(Authenticatable $user): ?CarbonInterface
    {
        return $user instanceof Model ? $this->latest($user)?->created_at : null;
    }

    public function isExpired(Authenticatable $user): bool
    {
        $policy = $this->policy();
        $changedAt = $this->changedAt($user);

        return $policy->maxAgeDays !== null
            && $changedAt instanceof CarbonInterface
            && $changedAt->copy()->addDays($policy->maxAgeDays)->isPast();
    }

    public function policy(): PasswordPolicy
    {
        return $this->realms->current()->credentials()->password;
    }

    private function wasUsedRecently(Authenticatable $user, #[SensitiveParameter] string $password, int $window): bool
    {
        $hashes = [];
        $current = $user->getAuthPassword();

        if ($current !== '') {
            $hashes[] = $current;
        }

        if ($user instanceof Model) {
            $stored = $user->hasMany(PasswordHistory::class, 'user_id')
                ->latest('created_at')
                ->limit($window)
                ->pluck('hash')
                ->all();

            array_push($hashes, ...array_filter($stored, is_string(...)));
        }

        return array_any(array_slice(array_values(array_unique($hashes)), 0, $window), fn (string $hash) => $this->hasher->check($password, $hash));
    }

    private function latest(Model $user): ?PasswordHistory
    {
        $latest = $user->hasMany(PasswordHistory::class, 'user_id')->latest('created_at')->first();

        return $latest instanceof PasswordHistory ? $latest : null;
    }

    private function prune(Model $user): void
    {
        $keep = max(1, $this->policy()->history);

        $stale = $user->hasMany(PasswordHistory::class, 'user_id')
            ->latest('created_at')
            ->skip($keep)
            ->limit(PHP_INT_MAX)
            ->pluck('id');

        if ($stale->isNotEmpty()) {
            PasswordHistory::query()->whereIn('id', $stale)->delete();
        }
    }
}
