<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\Events;

final readonly class RequiredActionCompleted
{
    public function __construct(
        public string $userId,
        public string $action,
    ) {}
}
