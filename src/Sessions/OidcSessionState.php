<?php

declare(strict_types=1);

namespace Lock\Server\Sessions;

use Lock\Server\Shared\Audit\SessionContext;

final class OidcSessionState implements SessionContext
{
    private const string AUTH_TIME_KEY = 'oidc.auth_time';

    private const string SID_KEY = 'oidc.sid';

    public function startOidcSession(string $sid): void
    {
        session()->put([
            self::AUTH_TIME_KEY => time(),
            self::SID_KEY => $sid,
        ]);
    }

    public function putAuthTime(int $authTime): void
    {
        session()->put(self::AUTH_TIME_KEY, $authTime);
    }

    public function sid(): ?string
    {
        $sid = session()->get(self::SID_KEY);

        return is_string($sid) && $sid !== '' ? $sid : null;
    }

    public function authTime(): ?int
    {
        $authTime = session()->get(self::AUTH_TIME_KEY);

        return is_numeric($authTime) ? (int) $authTime : null;
    }
}
