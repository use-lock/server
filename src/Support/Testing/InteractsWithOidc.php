<?php

declare(strict_types=1);

namespace Lock\Server\Support\Testing;

use DateInterval;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Foundation\Http\Middleware\ValidateCsrfToken;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Date;
use Illuminate\Support\Str;
use Illuminate\Testing\TestResponse;
use Lock\Server\Authentication\Context\LoginState;
use Lock\Server\Clients\ClientRepository;
use Lock\Server\Clients\Models\Client;
use Lock\Server\Sessions\OidcSessionState;
use Lock\Server\Shared\Authentication\AcrResolver;
use Lock\Server\Shared\Authentication\IdentityGuard;
use Lock\Server\Shared\Tokens\AccessTokenBearer;
use Lock\Server\Shared\Tokens\AccessTokenMinter;
use Lock\Server\SigningKeys\SigningKeyGenerator;
use Lock\Server\SigningKeys\SigningKeyStore;
use Lock\Server\Tokens\Guard\ClientPrincipal;
use Lock\Server\Tokens\Guard\CurrentAccessToken;
use Lock\Server\Tokens\Models\AccessToken;
use PHPUnit\Framework\Assert;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

/**
 * Test helpers for consumers of the package. Add to your Pest suite with
 * `uses(InteractsWithOidc::class)` (or `use` it in a PHPUnit TestCase).
 *
 * The host class must be a Laravel HTTP test case (Illuminate's
 * `Illuminate\Foundation\Testing\TestCase` or Orchestra Testbench's) — the
 * abstract method declarations below pin exactly what the trait needs.
 */
trait InteractsWithOidc
{
    private ?Client $oidcDefaultClient = null;

    /**
     * @return static
     */
    abstract public function actingAs(Authenticatable $user, $guard = null);

    /**
     * @param  array<string, mixed>  $data
     * @return static
     */
    abstract public function withSession(array $data);

    /**
     * @param  array<string, string>  $headers
     * @return TestResponse<Response>
     */
    abstract public function get($uri, array $headers = []);

    /**
     * @param  array<string, mixed>  $data
     * @param  array<string, string>  $headers
     * @return TestResponse<Response>
     */
    abstract public function post($uri, array $data = [], array $headers = []);

    /**
     * @param  string|array<int, string>|null  $middleware
     * @return static
     */
    abstract public function withoutMiddleware($middleware = null);

    /**
     * Authenticate on the identity guard and seed the session keys the
     * authorization grant reads: `oidc.auth_time`, `oidc.amr`,
     * `oidc.id_token_claims`, `oidc.access_token_claims`.
     *
     * `acr` is intentionally not a parameter: the grant derives it from
     * `$amr` through the bound {@see AcrResolver}.
     *
     * @param  array<string, mixed>  $idTokenClaims
     * @param  array<string, mixed>  $accessTokenClaims
     * @param  list<string>  $amr
     */
    public function actingAsIdentity(
        Authenticatable $user,
        array $idTokenClaims = [],
        array $accessTokenClaims = [],
        array $amr = [],
        ?int $authTime = null,
        ?string $guard = null,
    ): static {
        $this->actingAs($user, $guard ?? IdentityGuard::name());

        // withSession() starts the session store the typed writers below target.
        $this->withSession($amr === [] ? [] : [LoginState::AMR_KEY => $amr]);

        $state = app(LoginState::class);
        app(OidcSessionState::class)->putAuthTime($authTime ?? Date::now()->getTimestamp());

        if ($idTokenClaims !== [] || $accessTokenClaims !== []) {
            $state->putClaims($idTokenClaims, $accessTokenClaims);
        }

        return $this;
    }

    /**
     * Authenticate a user on the token guard with a token that grants the
     * listed scopes, without persisting anything.
     *
     * @param  list<string>  $scopes
     */
    public function actingAsOidcUser(Authenticatable $user, array $scopes = [], string $guard = 'oidc'): Authenticatable
    {
        if ($user instanceof AccessTokenBearer) {
            $user->withAccessToken(new CurrentAccessToken(new AccessToken(['user_id' => (string) $user->getAuthIdentifier(), 'scopes' => $scopes])));
        }

        $auth = app('auth');
        $auth->guard($guard)->setUser($user);
        $auth->shouldUse($guard);

        return $user;
    }

    /**
     * Authenticate a client on the token guard with a token that grants the
     * listed scopes, without persisting anything — the machine counterpart to
     * {@see actingAsOidcUser()}.
     *
     * @param  list<string>  $scopes
     */
    public function actingAsOidcClient(Client $client, array $scopes = [], string $guard = 'oidc'): ClientPrincipal
    {
        $principal = new ClientPrincipal($client->snapshot())
            ->withAccessToken(new CurrentAccessToken(new AccessToken(['client_id' => $client->getKey(), 'scopes' => $scopes])));

        $auth = app('auth');
        $auth->guard($guard)->setUser($principal);
        $auth->shouldUse($guard);

        return $principal;
    }

    /** @param  list<string>  $redirectUris */
    public function createOidcClient(
        string $name = 'Test Client',
        array $redirectUris = ['https://rp.test/callback'],
        bool $confidential = true,
    ): Client {
        return app(ClientRepository::class)->createAuthorizationCodeGrantClient($name, $redirectUris, $confidential);
    }

    /** A confidential `client_credentials` client — the machine counterpart to {@see createOidcClient()}. */
    public function createOidcMachineClient(string $name = 'Machine Client'): Client
    {
        return app(ClientRepository::class)->createClientCredentialsGrantClient($name);
    }

    /**
     * Create (or adopt) a client and point `oidc.clients.first_party.*` config at it.
     */
    public function withFirstPartyClient(?Client $client = null): Client
    {
        $client ??= $this->createOidcClient('First-Party App', ['https://app.test/callback']);

        config([
            'oidc.clients.first_party.client_id' => $client->client_id,
            'oidc.clients.first_party.trusted' => true,
        ]);

        return $client;
    }

    /**
     * Store a signing key for the current test so tokens can be minted. The
     * keypair is generated once per process and rotated into the key store
     * when the store holds none.
     */
    public function installSigningKey(): void
    {
        static $generated = null;

        $store = app(SigningKeyStore::class);

        try {
            $store->signingKey();

            return;
        } catch (Throwable) {
        }

        $generated ??= app(SigningKeyGenerator::class)->generate();
        $store->rotate($generated);
    }

    public function pkce(): PkcePair
    {
        return PkcePair::generate();
    }

    /**
     * Mint a real signed access token (with a persisted token record)
     * without driving the HTTP authorization flow. Creates and memoizes a
     * default client when none is given.
     *
     * @param  string[]  $scopes
     * @param  string[]  $audience
     */
    public function issueTokenFor(
        Authenticatable $user,
        ?Client $client = null,
        array $scopes = ['openid'],
        array $audience = [],
        ?DateInterval $ttl = null,
    ): string {
        $client ??= $this->oidcDefaultClient ??= $this->createOidcClient();

        return app(AccessTokenMinter::class)->mint(
            (string) $user->getAuthIdentifier(),
            $client->client_id,
            $scopes,
            $ttl ?? new DateInterval('PT1H'),
            $audience,
        )->toString();
    }

    /**
     * Mint a real signed userless access token — what `client_credentials`
     * issues — with a persisted token record, ready for a `Bearer` header.
     *
     * @param  string[]  $scopes
     * @param  string[]  $audience
     */
    public function issueClientToken(
        Client $client,
        array $scopes = [],
        array $audience = [],
        ?DateInterval $ttl = null,
    ): string {
        return app(AccessTokenMinter::class)->mint(
            null,
            $client->client_id,
            $scopes,
            $ttl ?? new DateInterval('PT1H'),
            $audience,
        )->toString();
    }

    /**
     * Drive the full authorization-code round-trip: authorize (with PKCE),
     * approve, and exchange the code at the token endpoint. The authorize and
     * approve legs assert; the token response is returned as-is so error
     * paths can be tested.
     *
     * URLs come from the named routes (`oidc.authorize`, `oidc.approve`,
     * `oidc.token`) so configured path overrides are honored. Bind a JSON
     * `ConsentView` returning `authToken` before calling this helper.
     *
     * The CSRF middleware exemption applied here is scoped to this call: any
     * exemption this method added is lifted again before returning, while
     * exemptions the calling test set up itself are left in place.
     *
     * @param  array<string, mixed>  $params  overrides for the authorize query (state, nonce, max_age, redirect_uri, ...)
     */
    public function authorizeAndApprove(
        Authenticatable $user,
        ?Client $client = null,
        string $scopes = 'openid',
        array $params = [],
        ?PkcePair $pkce = null,
    ): AuthorizationCodeResult {
        $client ??= $this->oidcDefaultClient ??= $this->createOidcClient();
        $pkce ??= PkcePair::generate();

        // The `web` group binds PreventRequestForgery on Laravel 13+ but
        // ValidateCsrfToken on older versions — both must be exempted.
        // withoutMiddleware() binds no-op container instances, so "not bound
        // yet" identifies the exemptions this call owns and must lift again.
        $csrfMiddleware = [ValidateCsrfToken::class, PreventRequestForgery::class];
        $ownedExemptions = array_filter($csrfMiddleware, fn (string $middleware): bool => ! app()->bound($middleware));

        $this->withoutMiddleware($csrfMiddleware);

        try {
            $guard = IdentityGuard::name();

            if (! Auth::guard($guard)->check()) {
                $this->actingAsIdentity($user, guard: $guard);
            }

            $query = array_merge([
                'client_id' => $client->client_id,
                'redirect_uri' => $client->redirect_uris[0] ?? 'https://rp.test/callback',
                'response_type' => 'code',
                'scope' => $scopes,
                'state' => Str::random(16),
                'nonce' => Str::random(16),
                'code_challenge' => $pkce->challenge,
                'code_challenge_method' => 'S256',
            ], $params);

            $authorize = $this->get(route('oidc.authorize').'?'.http_build_query($query));

            // Trusted clients and already-granted scopes skip consent entirely.
            if ($authorize->isRedirect()) {
                $approve = $authorize;
            } else {
                $authorize->assertOk();

                // json() would throw on a non-JSON view before the failure below can fire.
                $decoded = json_decode((string) $authorize->getContent(), true);
                $authToken = is_array($decoded) ? ($decoded['authToken'] ?? null) : null;

                if (! is_string($authToken) || $authToken === '') {
                    Assert::fail('The consent view did not return an authToken. If your app binds a custom ConsentView, bind a JSON ConsentView for this test before calling authorizeAndApprove().');
                }

                $approve = $this->post(route('oidc.approve'), ['auth_token' => $authToken]);
                $approve->assertRedirect();
            }

            parse_str((string) parse_url((string) $approve->headers->get('Location'), PHP_URL_QUERY), $callback);

            if (! isset($callback['code'])) {
                Assert::fail('Authorization did not yield a code. Redirected to: '.$approve->headers->get('Location'));
            }

            $tokenRequest = [
                'grant_type' => 'authorization_code',
                'client_id' => $client->client_id,
                'redirect_uri' => $query['redirect_uri'],
                'code' => $callback['code'],
                'code_verifier' => $pkce->verifier,
            ];

            if ($client->secret !== null) {
                $tokenRequest['client_secret'] = $client->secret;
            }

            return AuthorizationCodeResult::fromResponse($this->post(route('oidc.token'), $tokenRequest));
        } finally {
            foreach ($ownedExemptions as $middleware) {
                app()->forgetInstance($middleware);
            }
        }
    }
}
