<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\Pipeline;

use Illuminate\Support\Facades\Log;
use Lock\Server\Shared\Protocol\ProtocolClaims;
use Lock\Server\Shared\Protocol\TokenPipelineState;

class LoginApi
{
    use TokenPipelineState;

    private bool $mfaRequired = false;

    /** @var array<string, mixed> */
    private array $idTokenClaims = [];

    /** @var list<string> */
    private array $requiredActions = [];

    public function requireMfa(): void
    {
        $this->mfaRequired = true;
    }

    /**
     * Holds the login until the user completes this action. The demand lasts
     * for this login only — an action that should outlive it belongs in a
     * RequiredAction implementation that derives it from state. An unregistered
     * key is refused rather than silently stranding the user on a screen that
     * does not exist.
     */
    public function requireAction(string $key): void
    {
        $this->requiredActions[] = $key;
    }

    public function setIdTokenClaim(string $name, mixed $value): void
    {
        if (ProtocolClaims::isReserved($name)) {
            Log::warning("oidc: postLogin refused to set protected id_token claim [{$name}]");

            return;
        }

        $this->idTokenClaims[$name] = $value;
    }

    public function mfaRequired(): bool
    {
        return $this->mfaRequired;
    }

    /** @return array<string, mixed> */
    public function idTokenClaims(): array
    {
        return $this->idTokenClaims;
    }

    /** @return list<string> */
    public function requiredActions(): array
    {
        return array_values(array_unique($this->requiredActions));
    }
}
