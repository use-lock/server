<?php

declare(strict_types=1);

namespace Lock\Server\Sessions;

use DateTimeImmutable;
use Lock\Server\Sessions\Models\OidcSession;
use Lock\Server\Shared\Realms\IssuerResolver;
use Lock\Server\Shared\SigningKeys\Keyring;

class LogoutTokenBuilder
{
    private const string EVENT = 'http://schemas.openid.net/event/backchannel-logout';

    public function __construct(
        private readonly IssuerResolver $issuer,
        private readonly Keyring $keyring,
    ) {}

    public function build(OidcSession $session, string $clientId): string
    {
        $now = new DateTimeImmutable;

        $builder = $this->keyring->builder()
            ->withHeader('typ', 'logout+jwt')
            ->issuedBy($this->issuer->url())
            ->permittedFor($clientId)
            ->identifiedBy(bin2hex(random_bytes(16)))
            ->issuedAt($now)
            ->expiresAt($now->modify('+120 seconds'))
            ->relatedTo($session->user_id)
            ->withClaim('sid', $session->id)
            ->withClaim('events', (object) [self::EVENT => (object) []]);

        return $this->keyring->sign($builder);
    }
}
