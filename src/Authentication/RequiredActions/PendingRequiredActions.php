<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\RequiredActions;

/**
 * The session-held state between a login that still owes the realm something
 * and the screen that settles it. It holds only who is mid-login: what they
 * still owe is derived on every request, so the record can never disagree
 * with the realm's current rules.
 */
final readonly class PendingRequiredActions
{
    private const string USER_ID_KEY = 'required_actions.id';

    private const string REMEMBER_KEY = 'required_actions.remember';

    public function __construct(
        public int|string $userId,
        public bool $remember,
    ) {}

    public function store(): void
    {
        session()->put([
            self::USER_ID_KEY => $this->userId,
            self::REMEMBER_KEY => $this->remember,
        ]);
    }

    public static function find(): ?self
    {
        $userId = session()->get(self::USER_ID_KEY);

        if (! is_int($userId) && ! is_string($userId)) {
            return null;
        }

        return new self($userId, (bool) session()->get(self::REMEMBER_KEY, false));
    }

    public static function forget(): void
    {
        session()->forget([self::USER_ID_KEY, self::REMEMBER_KEY]);
    }
}
