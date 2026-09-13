<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\Ui\Views;

final readonly class PasswordUpdatePrompt
{
    /**
     * @param  bool  $requiresCurrentPassword  false mid-login, where the user proved a credential moments ago
     * @param  bool  $expired  whether the realm's rotation window is what brought the user here
     */
    public function __construct(
        public bool $requiresCurrentPassword,
        public bool $expired = false,
        public ?string $status = null,
    ) {}
}
