<?php

declare(strict_types=1);

namespace Lock\Server\Tokens\Guard;

use DateTimeInterface;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Illuminate\Support\Traits\Macroable;
use Lcobucci\JWT\Token\Plain;
use Lock\Server\Shared\Clients\Client;
use Lock\Server\Shared\Clients\Clients;
use Lock\Server\Shared\Realms\RealmAudiences;
use Lock\Server\Shared\Tokens\AccessTokenBearer;
use Lock\Server\Tokens\Concerns\ResolvesTokenUser;
use Lock\Server\Tokens\Http\Middleware\CheckAudience;
use Lock\Server\Tokens\Models\AccessToken;
use Lock\Server\Tokens\TokenInspector;

/**
 * RFC 9068 §4: accept only tokens addressed to the realm's resource audiences;
 * client IDs are not resource audiences. CheckAudience may narrow them further.
 * The principal is the token's user, or ClientPrincipal for a userless token.
 *
 * Use this guard's configured provider, not ResolvesTokenUser: the latter uses
 * the identity guard, which may have a different provider.
 */
class AccessTokenGuard implements Guard
{
    use GuardHelpers, Macroable;

    public function __construct(
        private readonly TokenInspector $inspector,
        UserProvider $provider,
        private Request $request,
    ) {
        $this->setProvider($provider);
    }

    public function user(): ?Authenticatable
    {
        if ($this->user !== null) {
            return $this->user;
        }

        $jwt = $this->request->bearerToken();

        if ($jwt === null) {
            return null;
        }

        $token = $this->verifyBearerToken($jwt);

        if (! $token instanceof AccessToken) {
            return null;
        }

        $principal = $this->principalFor($token);

        if (! $principal instanceof Authenticatable) {
            return null;
        }

        return $this->user = $principal instanceof AccessTokenBearer
            ? $principal->withAccessToken(new CurrentAccessToken($token))
            : $principal;
    }

    /**
     * @param  array<string, mixed>  $credentials
     */
    public function validate(array $credentials = []): bool
    {
        $request = $credentials['request'] ?? null;

        if (! $request instanceof Request) {
            return false;
        }

        return new self($this->inspector, $this->provider, $request)->user() instanceof Authenticatable;
    }

    public function setRequest(Request $request): static
    {
        $this->request = $request;

        return $this;
    }

    /**
     * A token carrying a subject authenticates that user and nobody else, so an unresolvable one is
     * rejected rather than falling back to the client. A userless token — `client_credentials`, or
     * an exchange without a subject — authenticates its client instead.
     */
    private function principalFor(AccessToken $token): ?Authenticatable
    {
        $userId = $token->getAttribute('user_id');

        if (is_string($userId)) {
            return $this->provider->retrieveById($userId);
        }

        $client = app(Clients::class)->findByKey($token->client_id, $token->realm);

        return $client instanceof Client && ! $client->revoked ? new ClientPrincipal($client) : null;
    }

    /**
     * Named apart from GuardHelpers::authenticate(), which the Guard contract expects to take no
     * arguments and return a non-nullable Authenticatable, so it is not silently overridden.
     */
    private function verifyBearerToken(string $jwt): ?AccessToken
    {
        $parsed = $this->inspector->parse($jwt);

        if (! $parsed instanceof Plain || $parsed->headers()->get('typ') !== 'at+jwt') {
            return null;
        }

        $exp = $parsed->claims()->get('exp');
        $expiry = $exp instanceof DateTimeInterface ? $exp->getTimestamp() : (is_numeric($exp) ? (int) $exp : 0);

        if ($expiry <= time()) {
            return null;
        }

        $token = $this->inspector->tokenForParsed($parsed);

        if (! $token instanceof AccessToken || $token->isRevoked()) {
            return null;
        }

        $audience = $this->normalizeAudience($parsed->claims()->get('aud'));

        // Resolved per call, not held: the guard instance outlives a request (see setRequest),
        // while the realm it serves is resolved from the current one.
        if (! app(RealmAudiences::class)->accepts($audience)) {
            return null;
        }

        $this->request->attributes->set('oidc_token_audience', $audience);

        return $token;
    }

    /** @return list<string> */
    private function normalizeAudience(mixed $aud): array
    {
        return array_values(array_filter(is_array($aud) ? $aud : [$aud], is_string(...)));
    }
}
