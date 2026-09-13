<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\RequiredActions;

use Lock\Server\Authentication\Contracts\RequiredAction;

/**
 * The actions this deployment knows about. Registration order is the order
 * the user is walked through them, so the package registers the cheapest and
 * most fundamental first: an unverified address may not even belong to the
 * person at the keyboard.
 */
final class RequiredActionRegistry
{
    /** @var list<RequiredAction> */
    private array $actions = [];

    public function register(RequiredAction ...$actions): void
    {
        foreach ($actions as $action) {
            $this->actions[] = $action;
        }
    }

    /** @return list<RequiredAction> */
    public function all(): array
    {
        return $this->actions;
    }

    public function find(string $key): ?RequiredAction
    {
        foreach ($this->actions as $action) {
            if ($action->key() === $key) {
                return $action;
            }
        }

        return null;
    }

    public function has(string $key): bool
    {
        return $this->find($key) instanceof RequiredAction;
    }
}
