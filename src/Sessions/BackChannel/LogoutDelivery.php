<?php

declare(strict_types=1);

namespace Lock\Server\Sessions\BackChannel;

use Carbon\CarbonImmutable;
use Lock\Server\Sessions\Models\OidcSession;
use Lock\Server\Shared\Clients\Client;

final readonly class LogoutDelivery
{
    public function __construct(
        public string $sid,
        public string $userId,
        public string $clientId,
        public ?string $uri,
        public ?CarbonImmutable $retryUntil,
    ) {}

    public static function from(OidcSession $session, Client $client): self
    {
        return new self(
            $session->id,
            $session->user_id,
            $client->clientId,
            $client->backchannelLogoutUri,
            $session->logoutRetryDeadline()?->toImmutable(),
        );
    }
}
