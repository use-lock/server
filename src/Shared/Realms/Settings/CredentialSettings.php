<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Realms\Settings;

final readonly class CredentialSettings
{
    /**
     * @param  list<string>  $challengeProviders  factor providers a login challenge may be satisfied with
     * @param  int  $totpWindow  accepted clock drift in 30-second steps
     * @param  int  $recoveryCodes  codes generated per set
     * @param  PasswordPolicy  $password  what a new password must satisfy and when one expires
     */
    public function __construct(
        public array $challengeProviders = ['totp', 'webauthn'],
        public int $totpSecretLength = 16,
        public int $totpWindow = 1,
        public int $recoveryCodes = 8,
        public PasswordPolicy $password = new PasswordPolicy,
    ) {}

    public static function fromConfig(): self
    {
        return new self(
            challengeProviders: array_values(array_filter(
                (array) config('oidc.credentials.challenge_providers', ['totp', 'webauthn']),
                is_string(...),
            )),
            totpSecretLength: (int) config('oidc.credentials.totp_secret_length', 16),
            totpWindow: (int) config('oidc.credentials.totp_window', 1),
            recoveryCodes: (int) config('oidc.credentials.recovery_codes', 8),
            password: PasswordPolicy::fromConfig(),
        );
    }
}
