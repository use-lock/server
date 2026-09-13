<?php

declare(strict_types=1);

namespace Lock\Server\Sessions\Listeners;

use Illuminate\Auth\Events\Login;
use Lock\Server\Sessions\Contracts\SessionTokenProvider;
use Lock\Server\Sessions\SessionTokenGuard;
use Lock\Server\Shared\Clients\FirstPartyClientConfig;
use Throwable;

class EstablishSessionToken
{
    public function __construct(
        private readonly SessionTokenProvider $tokens,
        private readonly FirstPartyClientConfig $firstPartyClient,
    ) {}

    public function handle(Login $event): void
    {
        if ($event->guard !== SessionTokenGuard::name()) {
            return;
        }

        if (! $this->firstPartyClient->isConfigured()) {
            return;
        }

        try {
            $this->tokens->establish($event->user);
        } catch (Throwable $e) {
            report($e);
        }
    }
}
