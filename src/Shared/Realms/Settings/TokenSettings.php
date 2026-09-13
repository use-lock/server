<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Realms\Settings;

use DateInterval;

final readonly class TokenSettings
{
    /**
     * @param  int  $accessTokenLifetime  seconds
     * @param  int  $idTokenLifetime  seconds
     * @param  int  $clientCredentialsLifetime  seconds
     * @param  int  $refreshTokenLifetime  seconds; the idle cap on a session — a refresh token unused for this long is dead
     * @param  int  $passwordResetLifetime  seconds a password reset link stays valid
     */
    public function __construct(
        public int $accessTokenLifetime = 900,
        public int $idTokenLifetime = 3600,
        public int $clientCredentialsLifetime = 3600,
        public int $refreshTokenLifetime = 1209600,
        public int $passwordResetLifetime = 3600,
    ) {}

    public static function fromConfig(): self
    {
        return new self(
            accessTokenLifetime: (int) config('oidc.tokens.access_token', 900),
            idTokenLifetime: (int) config('oidc.tokens.id_token', 3600),
            clientCredentialsLifetime: (int) config('oidc.tokens.client_credentials', 3600),
            refreshTokenLifetime: (int) config('oidc.tokens.refresh_token', 1209600),
            passwordResetLifetime: (int) config('oidc.tokens.password_reset', 3600),
        );
    }

    public function accessToken(): DateInterval
    {
        return $this->seconds($this->accessTokenLifetime);
    }

    public function clientCredentials(): DateInterval
    {
        return $this->seconds($this->clientCredentialsLifetime);
    }

    public function refreshToken(): DateInterval
    {
        return $this->seconds($this->refreshTokenLifetime);
    }

    private function seconds(int $seconds): DateInterval
    {
        return new DateInterval('PT'.max($seconds, 1).'S');
    }
}
