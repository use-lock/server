<?php

declare(strict_types=1);

/**
 * OAuth 2.1 §4.1.1 / §4.1.2.1 (authorization request validation and error responses), §7.6 (PKCE required);
 * RFC 7636 §4.4.1; RFC 8252 §7.3 (loopback redirects); OpenID Connect Core §3.1.2.1 (GET and POST, prompt, max_age,
 * id_token_hint), §3.1.2.6 (error codes); RFC 9207 §2 (iss); OAuth 2.0 Multiple Response Type Encoding Practices §2.1
 */

use Illuminate\Contracts\Support\Responsable;
use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Foundation\Http\Middleware\ValidateCsrfToken;
use Illuminate\Support\Facades\URL;
use Illuminate\Testing\TestResponse;
use Lock\Server\Authentication\Pipeline\LoginEvent;
use Lock\Server\Authentication\Pipeline\PostLoginPipeline;
use Lock\Server\Clients\ClientRepository;
use Lock\Server\Credentials\TotpFactorProvider;
use Lock\Server\Shared\Consents\ConsentView;
use Lock\Server\Shared\Realms\IssuerResolver;
use Lock\Server\Support\Testing\InteractsWithOidc;
use PragmaRX\Google2FA\Google2FA;
use Symfony\Component\HttpFoundation\Response;
use Workbench\App\Models\User;

uses(InteractsWithOidc::class);

beforeEach(function (): void {
    $this->withoutMiddleware([ValidateCsrfToken::class, PreventRequestForgery::class]);
    fakeConsentViewUsing(fn (array $parameters) => response()->json(['authToken' => $parameters['authToken']]));

    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'email_verified_at' => now(), 'password' => 'x']);
    $this->client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/callback']);
    $this->pkce = $this->pkce();
});

/**
 * @param  array<string, mixed>  $overrides
 * @return array<string, mixed>
 */
function authorizeParameters(mixed $test, array $overrides): array
{
    return array_filter(array_merge([
        'client_id' => $test->client->id,
        'redirect_uri' => 'https://rp.test/callback',
        'response_type' => 'code',
        'scope' => 'openid',
        'state' => 'st4te',
        'code_challenge' => $test->pkce->challenge,
        'code_challenge_method' => 'S256',
    ], $overrides), fn (mixed $value): bool => $value !== null);
}

/**
 * @param  array<string, mixed>  $overrides
 * @return TestResponse<Response>
 */
function authorizeWith(mixed $test, array $overrides, ?int $authTime = null): TestResponse
{
    return $test->actingAsIdentity($test->user, authTime: $authTime ?? time() - 60)
        ->get('/oauth/authorize?'.http_build_query(authorizeParameters($test, $overrides)));
}

/**
 * @param  array<string, mixed>  $overrides
 * @return TestResponse<Response>
 */
function authorizeAsGuest(mixed $test, array $overrides = []): TestResponse
{
    return $test->get('/oauth/authorize?'.http_build_query(authorizeParameters($test, $overrides)));
}

/**
 * @param  TestResponse<Response>  $response
 * @return array<string, string>
 */
function redirectParams(TestResponse $response): array
{
    $response->assertRedirect();
    expect($response->headers->get('Location'))->toStartWith('https://rp.test/callback?');
    parse_str((string) parse_url((string) $response->headers->get('Location'), PHP_URL_QUERY), $params);

    return $params;
}

// RFC 6749 §4.1.2.1: the resource owner is informed, never redirected, and no client authentication is challenged.
it('rejects an unknown or missing client without redirecting', function (?string $clientId): void {
    authorizeWith($this, ['client_id' => $clientId])
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_request')
        ->assertHeaderMissing('WWW-Authenticate');
})->with(['unknown' => 'nope', 'missing' => null]);

// OAuth 2.1 §4.1.3 / §7.5 — exact redirect-URI matching
it('rejects a redirect_uri that is not an exact registered match without redirecting', function (): void {
    authorizeWith($this, ['redirect_uri' => 'https://rp.test/callback/extra'])
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_request');
});

it('falls back to the single registered redirect_uri and requires one when several are registered', function (): void {
    $view = authorizeWith($this, ['redirect_uri' => null])->assertOk();
    $approve = $this->post('/oauth/authorize/consent', ['auth_token' => $view->json('authToken')]);

    expect(redirectParams($approve))->toHaveKey('code');

    $this->client->forceFill(['redirect_uris' => ['https://rp.test/callback', 'https://rp.test/other']])->save();

    authorizeWith($this, ['redirect_uri' => null])
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_request');
});

// RFC 8252 §7.3
it('accepts a loopback redirect_uri on any port', function (): void {
    $this->client->forceFill(['redirect_uris' => ['http://127.0.0.1:8080/cb']])->save();

    authorizeWith($this, ['redirect_uri' => 'http://127.0.0.1:53211/cb'])->assertOk();
    authorizeWith($this, ['redirect_uri' => 'http://127.0.0.1:53211/other'])->assertStatus(400);
});

// OAuth 2.1 §4.1.1 / §7.6 — PKCE with S256 for every client
it('rejects a missing code_challenge or the plain method on the redirect URI', function (array $overrides): void {
    $params = redirectParams(authorizeWith($this, $overrides));

    expect($params['error'])->toBe('invalid_request')
        ->and($params['state'])->toBe('st4te');
})->with([
    'no PKCE' => [['code_challenge' => null, 'code_challenge_method' => null]],
    'plain method' => [['code_challenge_method' => 'plain']],
]);

it('reports request errors to the client on the redirect URI with the state', function (array $overrides, string $error): void {
    $params = redirectParams(authorizeWith($this, $overrides));

    expect($params['error'])->toBe($error)
        ->and($params['state'])->toBe('st4te');
})->with([
    'unsupported response_type' => [['response_type' => 'token'], 'unsupported_response_type'],
    'unknown scope' => [['scope' => 'openid nope'], 'invalid_scope'],
    'resource the client may not request' => [['resource' => 'https://api.internal/orders'], 'invalid_target'],
    'relative resource' => [['resource' => 'api.internal/orders'], 'invalid_target'],
    'response_mode other than query' => [['response_mode' => 'fragment'], 'invalid_request'],
    'request object' => [['request' => 'eyJhbGciOiJub25lIn0.e30.'], 'request_not_supported'],
    'request_uri' => [['request_uri' => 'https://rp.test/request.jwt'], 'request_uri_not_supported'],
    'unknown prompt' => [['prompt' => 'wizard'], 'invalid_request'],
    'prompt=none with another value' => [['prompt' => 'none login'], 'invalid_request'],
    'malformed max_age' => [['max_age' => '-1'], 'invalid_request'],
    'unverifiable id_token_hint' => [['id_token_hint' => 'not.a.jwt'], 'invalid_request'],
]);

it('accepts response_mode=query', function (): void {
    authorizeWith($this, ['response_mode' => 'query'])->assertOk();
});

it('reports a client without the authorization_code grant to the client', function (): void {
    $this->client->forceFill(['grant_types' => ['client_credentials']])->save();

    expect(redirectParams(authorizeWith($this, []))['error'])->toBe('unauthorized_client');
});

// RFC 6749 §4.1.2.1 — denial
it('redirects a denied consent with access_denied and the state', function (): void {
    $view = authorizeWith($this, [])->assertOk();

    $params = redirectParams($this->delete('/oauth/authorize/consent', ['auth_token' => $view->json('authToken')]));

    expect($params['error'])->toBe('access_denied')
        ->and($params['state'])->toBe('st4te')
        ->and($params)->not->toHaveKey('code');
});

it('refuses to complete a consent with a foreign auth token', function (): void {
    authorizeWith($this, [])->assertOk();

    $this->post('/oauth/authorize/consent', ['auth_token' => 'forged'])->assertForbidden();
});

// OIDC Core §3.1.2.1 — GET and POST
it('accepts the authorization request as a POST read from the body only', function (): void {
    $view = $this->actingAsIdentity($this->user, authTime: time() - 60)
        ->post('/oauth/authorize', authorizeParameters($this, []))
        ->assertOk();

    expect(redirectParams($this->post('/oauth/authorize/consent', ['auth_token' => $view->json('authToken')])))->toHaveKey('code');

    $this->actingAsIdentity($this->user, authTime: time() - 60)
        ->post('/oauth/authorize?'.http_build_query(authorizeParameters($this, [])), ['scope' => 'openid'])
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_request');
});

// OAuth 2.1 §4.1.1 / RFC 6749 §3.1 — duplicate parameters
it('rejects duplicated parameters', function (): void {
    $params = redirectParams($this->actingAsIdentity($this->user, authTime: time() - 60)
        ->get('/oauth/authorize?'.http_build_query(authorizeParameters($this, [])).'&scope=openid'));

    expect($params['error'])->toBe('invalid_request')
        ->and($params['state'])->toBe('st4te');

    $this->actingAsIdentity($this->user, authTime: time() - 60)
        ->get('/oauth/authorize?'.http_build_query(authorizeParameters($this, [])).'&client_id='.$this->client->id)
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_request');

    $parameters = authorizeParameters($this, []);
    $body = http_build_query($parameters).'&state=other';

    expect(redirectParams($this->actingAsIdentity($this->user, authTime: time() - 60)
        ->call('POST', '/oauth/authorize', $parameters, [], [], ['CONTENT_TYPE' => 'application/x-www-form-urlencoded'], $body))['error'])
        ->toBe('invalid_request');
});

// OIDC Core §3.1.2.1 — max_age
it('forces re-authentication when the session is older than max_age', function (?int $authTime, string $maxAge): void {
    if ($authTime === null) {
        $this->actingAs($this->user, 'identity')
            ->get('/oauth/authorize?'.http_build_query(authorizeParameters($this, ['max_age' => $maxAge])))
            ->assertRedirect();
    } else {
        authorizeWith($this, ['max_age' => $maxAge], authTime: $authTime)->assertRedirect();
    }

    expect(auth('identity')->guest())->toBeTrue();
})->with([
    'stale session' => [time() - 3600, '300'],
    'max_age=0' => [time() - 1, '0'],
    'no auth_time recorded' => [null, '300'],
]);

it('proceeds when the session is fresh enough for max_age', function (): void {
    authorizeWith($this, ['max_age' => '300'])->assertOk();
});

// OIDC Core §3.1.2.1 / §3.1.2.6 — prompt
it('answers prompt=none without interaction', function (bool $authenticated, array $overrides, string $error): void {
    $response = $authenticated
        ? authorizeWith($this, ['prompt' => 'none', ...$overrides])
        : authorizeAsGuest($this, ['prompt' => 'none', ...$overrides]);

    $params = redirectParams($response);

    expect($params['error'])->toBe($error)
        ->and($params['state'])->toBe('st4te')
        ->and(auth('identity')->check())->toBe($authenticated);
})->with([
    'guest' => [false, [], 'login_required'],
    'expired max_age' => [true, ['max_age' => '10'], 'login_required'],
    'no prior consent' => [true, [], 'consent_required'],
]);

it('forces re-authentication for prompt=login and prompt=select_account', function (string $prompt): void {
    config(['oidc.login.route' => 'identity.login']);

    authorizeWith($this, ['prompt' => $prompt])->assertRedirect(route('identity.login'));

    expect(auth('identity')->guest())->toBeTrue()
        ->and(session('oidc.prompted_for_login'))->toBeTrue();
})->with(['login', 'select_account']);

it('redirects a guest to the configured login route name or path', function (string $loginRoute, string $destination): void {
    config(['oidc.login.route' => $loginRoute]);

    authorizeAsGuest($this)->assertRedirect($destination);

    expect(session('oidc.prompted_for_login'))->toBeTrue();
})->with([
    'route name' => ['identity.login', '/auth/login'],
    'literal path' => ['/custom/identity-login', '/custom/identity-login'],
]);

// OIDC Core §3.1.2.1 — id_token_hint
it('answers login_required when the id_token_hint names another user and proceeds for the current one', function (): void {
    $other = User::create(['name' => 'O', 'email' => 'o@example.com', 'email_verified_at' => now(), 'password' => 'x']);
    $foreignHint = $this->authorizeAndApprove($other, $this->client)->idToken;

    $params = redirectParams(authorizeWith($this, ['id_token_hint' => $foreignHint]));

    expect($params['error'])->toBe('login_required')
        ->and($params['state'])->toBe('st4te')
        ->and(auth('identity')->check())->toBeTrue();

    $ownHint = $this->authorizeAndApprove($this->user, $this->client)->idToken;

    expect(redirectParams(authorizeWith($this, ['id_token_hint' => $ownHint])))->toHaveKey('code');
});

// RFC 9207 §2
it('adds iss to code and error redirects', function (): void {
    $view = authorizeWith($this, [])->assertOk();

    $success = redirectParams($this->post('/oauth/authorize/consent', ['auth_token' => $view->json('authToken')]));
    $error = redirectParams(authorizeWith($this, ['response_type' => 'token']));

    expect($success)->toHaveKey('code')
        ->and($success['iss'])->toBe(app(IssuerResolver::class)->url())
        ->and($error['error'])->toBe('unsupported_response_type')
        ->and($error['iss'])->toBe(app(IssuerResolver::class)->url());
});

it('answers an Inertia request with 409 + X-Inertia-Location instead of an external redirect', function (): void {
    $view = authorizeWith($this, [])->assertOk();

    $approve = $this->post(route('oidc.approve'), ['auth_token' => $view->json('authToken')], ['X-Inertia' => 'true']);

    $approve->assertStatus(409);
    expect($approve->headers->get('X-Inertia-Location'))->toStartWith('https://rp.test/callback?');

    config()->set('oidc.clients.trusted', [(string) $this->client->getKey()]);

    $trusted = $this->actingAsIdentity($this->user, authTime: time() - 60)
        ->get('/oauth/authorize?'.http_build_query(authorizeParameters($this, [])), ['X-Inertia' => 'true']);

    $trusted->assertStatus(409);
    expect($trusted->headers->get('X-Inertia-Location'))->toStartWith('https://rp.test/callback?');
});

it('reports a known scope the client is not assigned as invalid_scope on the redirect URI', function (): void {
    $this->client->forceFill(['optional_scopes' => ['openid']])->save();

    $params = redirectParams(authorizeWith($this, ['scope' => 'openid email']));

    expect($params['error'])->toBe('invalid_scope')
        ->and($params['state'])->toBe('st4te');
});

it('does not resolve the consent view when authorization skips consent', function (): void {
    app()->bind(ConsentView::class, fn () => throw new RuntimeException('Consent must not be resolved.'));
    config()->set('oidc.clients.trusted', [(string) $this->client->getKey()]);

    expect(redirectParams(authorizeWith($this, [])))->toHaveKey('code');
});

it('accepts a responsable returned by a custom consent view', function (): void {
    fakeConsentViewUsing(fn (array $parameters): Responsable => new readonly class($parameters['authToken']) implements Responsable
    {
        public function __construct(private string $authToken) {}

        public function toResponse($request): Response
        {
            return response()->json(['authToken' => $this->authToken], 202);
        }
    });

    $view = authorizeWith($this, [])->assertStatus(202);

    expect(redirectParams($this->post('/oauth/authorize/consent', ['auth_token' => $view->json('authToken')])))->toHaveKey('code');
});

it('resumes posted authorization parameters after login and forced reauthentication', function (bool $authenticated): void {
    $this->user->forceFill(['password' => bcrypt('secret-password')])->save();
    $parameters = authorizeParameters($this, ['prompt' => 'login', 'nonce' => 'posted-nonce', 'acr_values' => 'mfa']);

    if ($authenticated) {
        $this->actingAsIdentity($this->user);
    }

    $this->post('/oauth/authorize?client_id=ignored&state=ignored', $parameters)
        ->assertRedirect('/auth/login')
        ->assertSessionMissing('oidc.consent_token');

    $login = $this->post(route('identity.login.store'), ['email' => 'm@example.com', 'password' => 'secret-password'])
        ->assertRedirect();

    parse_str((string) parse_url($login->headers->get('Location'), PHP_URL_QUERY), $resumedParameters);
    expect($resumedParameters)->toBe($parameters);

    $consent = $this->get($login->headers->get('Location'))->assertOk();
    $approved = $this->post(route('oidc.approve'), ['auth_token' => $consent->json('authToken')]);

    expect(redirectParams($approved))->toHaveKey('code')->toHaveKey('state', 'st4te');
})->with([false, true]);

it('uses the package login route by default', function (): void {
    authorizeAsGuest($this)->assertRedirect('/auth/login');
});

it('resumes posted authorization after email verification for guests and existing sessions', function (bool $authenticated): void {
    config(['oidc.authentication.email_verification_required' => true]);
    $this->user->forceFill(['email_verified_at' => null, 'password' => bcrypt('secret-password')])->save();

    if ($authenticated) {
        $this->actingAsIdentity($this->user);
    }

    $authorization = $this->post('/oauth/authorize', authorizeParameters($this, []));

    if ($authenticated) {
        $authorization->assertRedirect(route('identity.verification.notice'));
    } else {
        $authorization->assertRedirect('/auth/login');
        $this->post(route('identity.login.store'), ['email' => 'm@example.com', 'password' => 'secret-password'])
            ->assertRedirect(route('identity.verification.notice'));
    }

    $verification = $this->get(URL::temporarySignedRoute('identity.verification.verify', now()->addHour(), [
        'id' => $this->user->getKey(),
        'hash' => sha1($this->user->getEmailForVerification()),
    ]))->assertRedirect();

    $consent = $this->get($verification->headers->get('Location'))->assertOk();

    expect(redirectParams($this->post(route('oidc.approve'), ['auth_token' => $consent->json('authToken')])))
        ->toHaveKey('code')->toHaveKey('state', 'st4te');
})->with([false, true]);

it('replaces stale login context and consent when a different client requests authentication', function (): void {
    $this->user->forceFill(['password' => bcrypt('secret-password')])->save();
    $previous = authorizeWith($this, ['scope' => 'openid email'])->assertOk();
    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Another RP', ['https://other.test/callback']);
    $captured = null;
    app(PostLoginPipeline::class)->register(function (LoginEvent $event) use (&$captured): void {
        $captured = $event;
    });

    $this->post('/oauth/authorize', authorizeParameters($this, [
        'client_id' => $client->id,
        'redirect_uri' => 'https://other.test/callback',
        'prompt' => 'login',
        'acr_values' => 'mfa',
    ]))->assertRedirect('/auth/login')->assertSessionMissing('oidc.consent_token');

    $this->post(route('identity.login.store'), ['email' => 'm@example.com', 'password' => 'secret-password'])
        ->assertRedirect();

    expect($captured)->toBeInstanceOf(LoginEvent::class)
        ->and($captured->client?->clientId)->toBe((string) $client->id)
        ->and($captured->scopes)->toBe(['openid'])
        ->and($captured->requestedAcrValues)->toBe(['mfa']);

    $this->post(route('oidc.approve'), ['auth_token' => $previous->json('authToken')])->assertForbidden();
});

it('resumes posted authorization after the second-factor challenge', function (): void {
    $this->user->forceFill(['password' => bcrypt('secret-password')])->save();
    $factor = app(TotpFactorProvider::class)->enroll($this->user);
    $factor->forceFill(['confirmed_at' => now()])->save();

    $this->post('/oauth/authorize', authorizeParameters($this, []))->assertRedirect('/auth/login');
    $this->post(route('identity.login.store'), ['email' => 'm@example.com', 'password' => 'secret-password'])
        ->assertRedirect(route('identity.two-factor.login'));

    $challenge = $this->post(route('identity.two-factor.login.store'), [
        'code' => app(Google2FA::class)->getCurrentOtp($factor->secret),
    ])->assertRedirect();
    $consent = $this->get($challenge->headers->get('Location'))->assertOk();

    expect(redirectParams($this->post(route('oidc.approve'), ['auth_token' => $consent->json('authToken')])))
        ->toHaveKey('code')->toHaveKey('state', 'st4te');
});
