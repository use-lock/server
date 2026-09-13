<?php

declare(strict_types=1);

namespace Lock\Server\Protocol;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Contracts\Encryption\Encrypter;
use Illuminate\Support\Facades\Date;

/**
 * The token a logout prompt hands its view and the confirming POST returns.
 * It seals the post-logout target the prompting request validated with the
 * application encrypter, bound to the user who saw the prompt and to a
 * ten-minute window, so a confirmation cannot be replayed for another user
 * or steer the browser to a target no request validated.
 */
final readonly class LogoutConfirmation
{
    private const int TTL_MINUTES = 10;

    public function __construct(private Encrypter $encrypter) {}

    public function issue(Authenticatable $user, ?string $redirectUri, ?string $state): string
    {
        return $this->encrypter->encrypt([
            'sub' => (string) $user->getAuthIdentifier(),
            'redirect_uri' => $redirectUri,
            'state' => $state,
            'exp' => Date::now()->addMinutes(self::TTL_MINUTES)->getTimestamp(),
        ]);
    }

    /** @return array{redirect_uri: ?string, state: ?string}|null */
    public function verify(string $token, Authenticatable $user): ?array
    {
        try {
            $payload = $this->encrypter->decrypt($token);
        } catch (DecryptException) {
            return null;
        }

        if (! is_array($payload)
            || ($payload['sub'] ?? null) !== (string) $user->getAuthIdentifier()
            || (int) ($payload['exp'] ?? 0) <= Date::now()->getTimestamp()) {
            return null;
        }

        return [
            'redirect_uri' => is_string($payload['redirect_uri'] ?? null) ? $payload['redirect_uri'] : null,
            'state' => is_string($payload['state'] ?? null) ? $payload['state'] : null,
        ];
    }
}
