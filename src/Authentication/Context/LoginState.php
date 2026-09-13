<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\Context;

use Lock\Server\Shared\Authentication\LoginContext;
use Lock\Server\Shared\Authentication\LoginSnapshot;

final class LoginState implements LoginContext
{
    public const string AMR_KEY = 'oidc.amr';

    private const string ID_TOKEN_CLAIMS_KEY = 'oidc.id_token_claims';

    private const string ACCESS_TOKEN_CLAIMS_KEY = 'oidc.access_token_claims';

    private const string REQUESTED_ACTIONS_KEY = 'oidc.requested_actions';

    public function start(string $method): void
    {
        session()->put(self::AMR_KEY, $this->dedupe([$method]));
    }

    public function add(string ...$methods): void
    {
        session()->put(self::AMR_KEY, $this->dedupe([...$this->amr(), ...$methods]));
    }

    /**
     * @return list<string>
     */
    public function amr(): array
    {
        $amr = session()->get(self::AMR_KEY, []);

        return is_array($amr) ? array_values(array_filter($amr, is_string(...))) : [];
    }

    /**
     * @param  array<string, mixed>  $idToken
     * @param  array<string, mixed>  $accessToken
     */
    public function putClaims(array $idToken, array $accessToken): void
    {
        session()->put([
            self::ID_TOKEN_CLAIMS_KEY => $idToken,
            self::ACCESS_TOKEN_CLAIMS_KEY => $accessToken,
        ]);
    }

    /**
     * @return array<string, mixed>
     */
    public function idTokenClaims(): array
    {
        $claims = session()->get(self::ID_TOKEN_CLAIMS_KEY, []);

        return is_array($claims) ? $claims : [];
    }

    /**
     * @return array<string, mixed>
     */
    public function accessTokenClaims(): array
    {
        $claims = session()->get(self::ACCESS_TOKEN_CLAIMS_KEY, []);

        return is_array($claims) ? $claims : [];
    }

    /**
     * The actions the post-login pipeline asked for during this login. They
     * are not derivable from any state, so they stay here until the screen
     * that settles one reports it done.
     *
     * @param  list<string>  $keys
     */
    public function putRequestedActions(array $keys): void
    {
        $keys === []
            ? session()->forget(self::REQUESTED_ACTIONS_KEY)
            : session()->put(self::REQUESTED_ACTIONS_KEY, array_values(array_unique($keys)));
    }

    /**
     * @return list<string>
     */
    public function requestedActions(): array
    {
        $keys = session()->get(self::REQUESTED_ACTIONS_KEY, []);

        return is_array($keys) ? array_values(array_filter($keys, is_string(...))) : [];
    }

    public function completeRequestedAction(string $key): void
    {
        $this->putRequestedActions(array_values(array_diff($this->requestedActions(), [$key])));
    }

    public function snapshot(): LoginSnapshot
    {
        return new LoginSnapshot($this->amr(), $this->idTokenClaims(), $this->accessTokenClaims());
    }

    public function forget(): void
    {
        session()->forget([self::AMR_KEY, self::ID_TOKEN_CLAIMS_KEY, self::ACCESS_TOKEN_CLAIMS_KEY, self::REQUESTED_ACTIONS_KEY]);
    }

    /**
     * @param  array<int, mixed>  $methods
     * @return list<string>
     */
    private function dedupe(array $methods): array
    {
        return array_values(array_unique(array_filter($methods, is_string(...))));
    }
}
