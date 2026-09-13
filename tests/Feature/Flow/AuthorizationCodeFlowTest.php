<?php

declare(strict_types=1);

/**
 * OAuth 2.1 §4.1 authorization code grant + RFC 7636 PKCE (S256); OpenID Connect Core 1.0 §2 (acr, amr),
 * §3.1.3 (token response), §3.1.3.6 (at_hash); OpenID Connect Back-Channel Logout §2.1 (sid)
 */

use Illuminate\Foundation\Http\Middleware\ValidateCsrfToken;
use Illuminate\Http\JsonResponse;
use Illuminate\Testing\TestResponse;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Validator;
use Lock\Server\Authentication\Pipeline\LoginApi;
use Lock\Server\Authentication\Pipeline\LoginEvent;
use Lock\Server\Authentication\Pipeline\PostLoginPipeline;
use Lock\Server\Clients\ClientRepository;
use Lock\Server\Sessions\Models\SessionParticipant;
use Lock\Server\Sessions\OidcSessionRepository;
use Lock\Server\Support\Testing\InteractsWithOidc;
use Lock\Server\Tests\FeatureTestCase;
use Lock\Server\Tokens\Models\AccessToken;
use Lock\Server\Tokens\Models\AuthorizationCode;
use Lock\Server\Tokens\Pipeline\AccessTokenApi;
use Lock\Server\Tokens\Pipeline\AccessTokenPipeline;
use Lock\Server\Tokens\Pipeline\AuthorizationCodeEvent;
use Workbench\App\Models\User;

uses(InteractsWithOidc::class);

beforeEach(function (): void {
    $this->withoutMiddleware(ValidateCsrfToken::class);
    fakeConsentViewUsing(fn (array $parameters) => response()->json(['authToken' => $parameters['authToken']]));

    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'email_verified_at' => now(), 'password' => bcrypt('secret-password')]);
    $this->client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/callback']);
});

/**
 * @param  list<string>  $amr
 * @param  array<string, mixed>  $idTokenClaims
 * @param  array<string, mixed>  $accessTokenClaims
 * @param  array<string, mixed>  $params
 * @return TestResponse<JsonResponse>
 */
function completeAuthorizationCodeFlow(
    FeatureTestCase $test,
    array $amr = [],
    array $idTokenClaims = [],
    array $accessTokenClaims = [],
    ?string $sid = null,
    string $scopes = 'openid email',
    array $params = [],
): TestResponse {
    $test->actingAsIdentity($test->user, idTokenClaims: $idTokenClaims, accessTokenClaims: $accessTokenClaims, amr: $amr, authTime: time() - 60);

    if ($sid !== null) {
        $test->withSession(['oidc.sid' => $sid]);
    }

    return $test->authorizeAndApprove($test->user, $test->client, scopes: $scopes, params: ['state' => 'st4te', 'nonce' => 'n0nce', ...$params])->response;
}

it('issues a signed id_token and access token through the code + PKCE flow', function (): void {
    config(['app.url' => 'https://op.test', 'oidc.issuer' => null]);

    $response = completeAuthorizationCodeFlow($this)->assertOk()->assertJsonPath('scope', 'openid email');

    expect($response->json())->toHaveKeys(['access_token', 'refresh_token', 'id_token']);

    $idToken = parseIdToken($response->json('id_token'));
    $expectedAtHash = rtrim(strtr(base64_encode(substr(hash('sha256', $response->json('access_token'), true), 0, 16)), '+/', '-_'), '=');

    expect($idToken->claims()->get('iss'))->toBe('https://op.test')
        ->and($idToken->claims()->get('sub'))->toBe((string) $this->user->id)
        ->and($idToken->claims()->get('aud'))->toBe([$this->client->id])
        ->and($idToken->claims()->get('nonce'))->toBe('n0nce')
        ->and($idToken->claims()->get('auth_time'))->toBeInt()
        ->and($idToken->claims()->has('amr'))->toBeFalse()
        ->and($idToken->claims()->has('acr'))->toBeFalse()
        ->and($idToken->claims()->get('email'))->toBe('m@example.com')
        ->and($idToken->claims()->get('at_hash'))->toBe($expectedAtHash)
        ->and((new Validator)->validate($idToken, new SignedWith(new Sha256, InMemory::plainText(signingPublicKey()))))->toBeTrue()
        ->and($idToken->headers()->get('kid'))->toBe($this->getJson('/.well-known/jwks.json')->json('keys.0.kid'));
});

it('omits the id_token without the openid scope', function (): void {
    $response = completeAuthorizationCodeFlow($this, scopes: 'email')->assertOk();

    expect($response->json())->toHaveKey('access_token')
        ->and($response->json())->not->toHaveKey('id_token');
});

it('carries the login session amr, derived acr and postLogin claims into the issued tokens', function (): void {
    $response = completeAuthorizationCodeFlow(
        $this,
        amr: ['pwd', 'otp'],
        idTokenClaims: ['groups' => ['admin']],
        accessTokenClaims: ['tier' => 'gold', 'amr' => ['hax']],
    )->assertOk();

    $idToken = parseIdToken($response->json('id_token'));
    $accessToken = parseAccessToken($response->json('access_token'));

    expect($idToken->claims()->get('amr'))->toBe(['pwd', 'otp'])
        ->and($idToken->claims()->get('acr'))->toBe('2')
        ->and($idToken->claims()->get('groups'))->toBe(['admin'])
        ->and($accessToken->claims()->get('tier'))->toBe('gold')
        ->and($accessToken->claims()->has('amr'))->toBeFalse();
});

it('carries a real credential login and its postLogin claims through to the id_token', function (): void {
    app(PostLoginPipeline::class)->register(fn (LoginEvent $event, LoginApi $api) => $api->setIdTokenClaim('groups', ['admin']));

    $this->post(route('identity.login.store'), ['email' => 'm@example.com', 'password' => 'secret-password'])->assertRedirect();

    $idToken = parseIdToken($this->authorizeAndApprove($this->user, $this->client, scopes: 'openid')->idToken);

    expect($idToken->claims()->get('groups'))->toBe(['admin'])
        ->and($idToken->claims()->get('amr'))->toBe(['pwd'])
        ->and($idToken->claims()->get('acr'))->toBe('1');
});

it('emits the sid claim and records the client as a session participant', function (): void {
    $sid = app(OidcSessionRepository::class)->start((string) $this->user->id);

    $response = completeAuthorizationCodeFlow($this, amr: ['pwd'], sid: $sid)->assertOk();
    completeAuthorizationCodeFlow($this, amr: ['pwd'], sid: $sid)->assertOk();

    expect(parseIdToken($response->json('id_token'))->claims()->get('sid'))->toBe($sid)
        ->and(SessionParticipant::query()->where('session_id', $sid)->pluck('client_id')->all())->toBe([$this->client->id]);
});

it('applies authorization-code trigger claims to the issued access token', function (): void {
    app(AccessTokenPipeline::class)->register('authorization_code', function (AuthorizationCodeEvent $event, AccessTokenApi $api): void {
        expect($event->user->getAuthIdentifier())->toBe($this->user->id)
            ->and($event->client->key)->toBe((string) $this->client->id)
            ->and($event->scopes)->toBe(['openid', 'email']);

        $api->setAccessTokenClaim('project_id', 'p-1');
        $api->setAccessTokenClaim('via', $event->grantType);
    });

    $accessToken = parseAccessToken((string) completeAuthorizationCodeFlow($this)->assertOk()->json('access_token'));

    expect($accessToken->claims()->get('project_id'))->toBe('p-1')
        ->and($accessToken->claims()->get('via'))->toBe('authorization_code');
});

it('denies issuance before persisting when a trigger denies', function (): void {
    app(AccessTokenPipeline::class)->register('authorization_code', fn (AuthorizationCodeEvent $event, AccessTokenApi $api) => $api->deny('user_blocked'));

    completeAuthorizationCodeFlow($this)
        ->assertStatus(400)
        ->assertJsonPath('error', 'access_denied')
        ->assertJsonMissingPath('access_token');

    expect(AccessToken::query()->count())->toBe(0)
        ->and(AuthorizationCode::query()->sole()->revoked_at)->toBeNull();
});

it('issues the client default scopes without them being requested', function (): void {
    $this->client->forceFill(['default_scopes' => ['email']])->save();

    expect(completeAuthorizationCodeFlow($this, scopes: 'openid')->assertOk()->json('scope'))->toBe('openid email');
});
