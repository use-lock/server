<?php

declare(strict_types=1);

namespace Lock\Server\Sessions;

use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Session\Session;
use Lock\Server\Sessions\Models\OidcSession;
use Lock\Server\Sessions\Models\SessionParticipant;
use Lock\Server\Shared\Authentication\IdentityGuard;
use Lock\Server\Shared\Realms\RealmResolver;
use Lock\Server\Shared\Sessions\SessionEnded;
use Lock\Server\Shared\Sessions\Sessions;
use Lock\Server\Shared\Sessions\SessionSnapshot;

class OidcSessionRepository implements Sessions
{
    public function __construct(
        private readonly RealmResolver $realms,
        private readonly OidcSessionState $state,
        private readonly AuthFactory $auth,
    ) {}

    public function current(): SessionSnapshot
    {
        $sid = $this->state->sid();
        $session = $sid !== null ? $this->find($sid) : null;

        return new SessionSnapshot(
            realm: $this->realms->current()->identifier(),
            sid: $sid,
            authTime: $this->state->authTime(),
            expiresAt: $session?->expires_at?->toImmutable(),
            active: $session?->isActive() ?? false,
        );
    }

    public function get(string $sid): ?SessionSnapshot
    {
        $session = $this->find($sid);

        return $session instanceof OidcSession ? new SessionSnapshot(
            realm: $session->realm,
            sid: $session->id,
            authTime: null,
            expiresAt: $session->expires_at?->toImmutable(),
            active: $session->isActive(),
        ) : null;
    }

    public function end(?Session $session = null): void
    {
        $this->auth->guard(IdentityGuard::name())->logout();

        if ($session instanceof Session) {
            $session->invalidate();
            $session->regenerateToken();
        }
    }

    public function start(string $userId, ?string $browserSessionId = null): string
    {
        $session = new OidcSession;
        $session->realm = OidcSession::currentRealm();
        $session->user_id = $userId;
        $session->browser_session_id = $browserSessionId;
        $session->expires_at = now()->add($this->realms->current()->sessions()->absolute());
        $session->save();

        return $session->id;
    }

    public function find(string $sid): ?OidcSession
    {
        return OidcSession::query()->inRealm()->find($sid);
    }

    public function findByBrowserSession(string $browserSessionId): ?OidcSession
    {
        return OidcSession::query()->inRealm()->where('browser_session_id', $browserSessionId)->first();
    }

    /**
     * createOrFirst (not updateOrInsert) so the model's creating hook runs —
     * it generates the uuid key — while the unique (session_id, client_id) index
     * still absorbs concurrent inserts.
     *
     * @param  string  $clientKey  the client's primary key
     */
    public function recordParticipant(string $sid, string $clientKey): void
    {
        SessionParticipant::query()->createOrFirst(
            ['session_id' => $sid, 'client_id' => $clientKey],
            ['created_at' => now()],
        );
    }

    public function revoke(string $sid): void
    {
        if (OidcSession::query()->inRealm()->whereKey($sid)->whereNull('revoked_at')->update(['revoked_at' => now()]) > 0) {
            event(new SessionEnded($sid, $this->realms->current()->identifier()));
        }
    }
}
