<?php

declare(strict_types=1);

namespace Lock\Server\Sessions\Listeners;

use Illuminate\Auth\Events\Logout;
use Lock\Server\Sessions\Contracts\SessionTokenProvider;
use Lock\Server\Sessions\SessionTokenGuard;

class ForgetSessionToken
{
    public function __construct(private readonly SessionTokenProvider $tokens) {}

    public function handle(Logout $event): void
    {
        if ($event->guard !== SessionTokenGuard::name()) {
            return;
        }

        $this->tokens->forget();
    }
}
