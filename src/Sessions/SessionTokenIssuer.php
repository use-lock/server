<?php

declare(strict_types=1);

namespace Lock\Server\Sessions;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Session\Session;
use Illuminate\Support\Facades\Auth;
use Lock\Server\Sessions\Contracts\SessionTokenProvider;
use Lock\Server\Shared\Clients\Clients;
use Lock\Server\Shared\Realms\RealmResolver;
use Lock\Server\Shared\Scopes\Scope;
use Lock\Server\Shared\Scopes\ScopeRepository;
use Lock\Server\Shared\Tokens\AccessTokenMinter;
use Lock\Server\Shared\Tokens\AccessTokenRevoker;

/**
 * This is a singleton, so the session/auth stores and the first-party client
 * config must never be injected via the constructor — that would capture
 * request-scoped (or test-mutated) state on first resolution and leak it
 * across requests. They are resolved lazily, per call, inside each method.
 */
class SessionTokenIssuer implements SessionTokenProvider
{
    private const string SESSION_KEY = 'oidc.session_token';

    public function __construct(
        private readonly Clients $clients,
        private readonly AccessTokenMinter $minter,
        private readonly AccessTokenRevoker $revoker,
        private readonly ScopeRepository $scopes,
        private readonly RealmResolver $realms,
    ) {}

    public function currentToken(): ?string
    {
        $stored = $this->session()->get(self::SESSION_KEY);
        $currentUserId = $this->guard()->id();

        if (is_array($stored)
            && is_string($stored['jwt'] ?? null)
            && ($stored['realm'] ?? null) === $this->realms->current()->identifier()
            && ($stored['user_id'] ?? null) === ($currentUserId === null ? null : (string) $currentUserId)
            && ((int) ($stored['expires_at'] ?? 0)) - time() > $this->skew()) {
            return $stored['jwt'];
        }

        $user = $this->guard()->user();

        if ($user === null) {
            return null;
        }

        $this->establish($user);

        return $this->session()->get(self::SESSION_KEY)['jwt'] ?? null;
    }

    public function establish(Authenticatable $user): void
    {
        $client = $this->clients->firstParty();

        $prior = $this->session()->get(self::SESSION_KEY);

        if (is_array($prior) && is_string($prior['jti'] ?? null)) {
            $this->revoker->revoke($prior['jti']);
        }

        $token = $this->minter->mint(
            (string) $user->getAuthIdentifier(),
            $client->clientId,
            $this->defaultScopes(),
            $this->realms->current()->sessions()->token(),
        );

        $this->session()->put(self::SESSION_KEY, [
            'realm' => $client->realm,
            'jwt' => $token->jwt,
            'jti' => $token->jti,
            'user_id' => (string) $user->getAuthIdentifier(),
            'expires_at' => $token->expiresAt->getTimestamp(),
        ]);
    }

    public function forget(): void
    {
        $stored = $this->session()->get(self::SESSION_KEY);

        if (is_array($stored) && is_string($stored['jti'] ?? null)) {
            $this->revoker->revoke($stored['jti']);
        }

        $this->session()->forget(self::SESSION_KEY);
    }

    private function session(): Session
    {
        return app('session.store');
    }

    private function guard(): Guard
    {
        return Auth::guard(SessionTokenGuard::name());
    }

    /** @return string[] */
    private function defaultScopes(): array
    {
        $configured = $this->realms->current()->sessions()->tokenScopes;

        if ($configured !== null) {
            return $configured;
        }

        return $this->scopes->all()->reject(fn (Scope $scope): bool => $scope->hidden)->map(fn (Scope $scope): string => $scope->id)->values()->all();
    }

    private function skew(): int
    {
        return $this->realms->current()->sessions()->tokenRefreshSkew;
    }
}
