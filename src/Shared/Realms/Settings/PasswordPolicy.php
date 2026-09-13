<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Realms\Settings;

use Illuminate\Validation\Rules\Password;

final readonly class PasswordPolicy
{
    /**
     * @param  int  $minLength  characters a new password needs at least
     * @param  bool  $uncompromised  reject passwords found in a public breach (haveibeenpwned range lookup)
     * @param  int  $history  previous passwords (including the current one) a new password may not repeat; 0 disables the check
     * @param  int|null  $maxAgeDays  days after which a password counts as expired; null never expires
     */
    public function __construct(
        public int $minLength = 8,
        public bool $mixedCase = false,
        public bool $numbers = false,
        public bool $symbols = false,
        public bool $uncompromised = false,
        public int $history = 0,
        public ?int $maxAgeDays = null,
    ) {}

    public static function fromConfig(): self
    {
        $maxAgeDays = config('oidc.password_policy.max_age_days');

        return new self(
            minLength: (int) config('oidc.password_policy.min_length', 8),
            mixedCase: (bool) config('oidc.password_policy.mixed_case', false),
            numbers: (bool) config('oidc.password_policy.numbers', false),
            symbols: (bool) config('oidc.password_policy.symbols', false),
            uncompromised: (bool) config('oidc.password_policy.uncompromised', false),
            history: max(0, (int) config('oidc.password_policy.history', 0)),
            maxAgeDays: is_numeric($maxAgeDays) && (int) $maxAgeDays > 0 ? (int) $maxAgeDays : null,
        );
    }

    public function rule(): Password
    {
        $rule = Password::min($this->minLength);

        if ($this->mixedCase) {
            $rule->mixedCase();
        }

        if ($this->numbers) {
            $rule->numbers();
        }

        if ($this->symbols) {
            $rule->symbols();
        }

        if ($this->uncompromised) {
            $rule->uncompromised();
        }

        return $rule;
    }

    public function rotates(): bool
    {
        return $this->maxAgeDays !== null;
    }
}
