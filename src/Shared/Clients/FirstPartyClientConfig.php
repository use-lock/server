<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Clients;

use Lock\Server\Shared\Realms\Settings\ClientSettings;

final readonly class FirstPartyClientConfig
{
    /** @param string[] $additionalTrustedClientIds */
    private function __construct(
        private ?string $resolvedClientId,
        private bool $firstPartyTrusted,
        private array $additionalTrustedClientIds,
    ) {}

    public static function fromConfig(): self
    {
        return self::fromSettings(ClientSettings::fromConfig());
    }

    public static function fromSettings(ClientSettings $clients): self
    {
        return new self(
            resolvedClientId: $clients->firstPartyClientId,
            firstPartyTrusted: $clients->firstPartyTrusted,
            additionalTrustedClientIds: $clients->trustedClients,
        );
    }

    public function clientId(): ?string
    {
        return $this->resolvedClientId;
    }

    public function isConfigured(): bool
    {
        return $this->resolvedClientId !== null;
    }

    public function isTrusted(string|int $clientId): bool
    {
        $clientId = (string) $clientId;

        if ($this->resolvedClientId === $clientId) {
            return $this->firstPartyTrusted;
        }

        return in_array($clientId, $this->additionalTrustedClientIds, true);
    }
}
