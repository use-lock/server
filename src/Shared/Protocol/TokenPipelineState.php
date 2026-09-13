<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Protocol;

use Illuminate\Support\Facades\Log;

trait TokenPipelineState
{
    private ?string $denyReason = null;

    /** @var array<string, mixed> */
    private array $accessTokenClaims = [];

    /** @var array<string, mixed> */
    private array $context = [];

    public function deny(string $reason): void
    {
        $this->denyReason = $reason;
    }

    public function isDenied(): bool
    {
        return $this->denyReason !== null;
    }

    public function denyReason(): ?string
    {
        return $this->denyReason;
    }

    public function setAccessTokenClaim(string $name, mixed $value): void
    {
        if (ProtocolClaims::isAccessTokenReserved($name)) {
            Log::warning("oidc: refused protected access_token claim [{$name}]");

            return;
        }

        $this->accessTokenClaims[$name] = $value;
    }

    /** @return array<string, mixed> */
    public function accessTokenClaims(): array
    {
        return $this->accessTokenClaims;
    }

    /**
     * Share arbitrary data between triggers within the same pipeline run.
     * Unlike setAccessTokenClaim(), this never ends up in the minted token.
     */
    public function setContext(string $key, mixed $value): void
    {
        $this->context[$key] = $value;
    }

    public function context(string $key): mixed
    {
        return $this->context[$key] ?? null;
    }
}
