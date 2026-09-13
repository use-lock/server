<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\Ui\Views;

final readonly class PasswordResetRequestPrompt
{
    public function __construct(
        public ?string $status = null,
    ) {}
}
