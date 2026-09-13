<?php

declare(strict_types=1);

use Illuminate\Foundation\Http\Middleware\ValidateCsrfToken;
use Illuminate\Support\Collection;
use Illuminate\Support\Str;
use Illuminate\Testing\TestResponse;
use Lock\Server\Clients\ClientRepository;
use Lock\Server\Consents\ConsentRepository;
use Lock\Server\Consents\Models\Consent;
use Lock\Server\Scopes\ConfiguredScopeRepository;
use Lock\Server\Shared\Consents\ConsentStore;
use Lock\Server\Shared\Realms\RealmAudiences;
use Lock\Server\Shared\Realms\RealmResolver;
use Lock\Server\Shared\Scopes\Scope;
use Lock\Server\Shared\Scopes\ScopeRepository;
use Lock\Server\Shared\Tokens\AccessTokenRevoker;
use Lock\Server\Support\Testing\InteractsWithOidc;
use Lock\Server\Support\Testing\PkcePair;
use Lock\Server\Tests\FeatureTestCase;
use Lock\Server\Tokens\Models\AccessToken;
use Symfony\Component\HttpFoundation\Response;
use Workbench\App\Models\User;

uses(InteractsWithOidc::class);

beforeEach(function (): void {
    $this->withoutMiddleware(ValidateCsrfToken::class);
    fakeConsentViewUsing(fn (array $parameters) => response()->json(['authToken' => $parameters['authToken']]));

    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'email_verified_at' => now(), 'password' => 'x']);
    $this->client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/callback']);
});

/**
 * @return TestResponse<Response>
 */
function authorizeExpectingDecision(FeatureTestCase $test, string $scopes = 'openid'): TestResponse
{
    return $test->actingAsIdentity($test->user, authTime: time() - 60)
        ->get(route('oidc.authorize').'?'.http_build_query([
            'client_id' => $test->client->client_id,
            'redirect_uri' => 'https://rp.test/callback',
            'response_type' => 'code',
            'scope' => $scopes,
            'state' => 'st4te',
            'code_challenge' => PkcePair::generate()->challenge,
            'code_challenge_method' => 'S256',
        ]));
}

function realmResource(): string
{
    return app(RealmAudiences::class)->default()[0];
}

function storedConsent(FeatureTestCase $test): ?Consent
{
    return app(ConsentRepository::class)->findByKey((string) $test->user->id, $test->client->id, realmResource());
}

it('records the approved scopes as a consent', function (): void {
    $this->authorizeAndApprove($this->user, $this->client, 'openid email');

    expect(storedConsent($this))->not->toBeNull()
        ->and(storedConsent($this)?->scopes)->toBe(['openid', 'email'])
        ->and(storedConsent($this)?->revoked_at)->toBeNull();
});

it('does not record a consent when the user denies', function (): void {
    $view = authorizeExpectingDecision($this)->assertOk();

    $this->delete(route('oidc.deny'), ['auth_token' => $view->json('authToken')])->assertRedirect();

    expect(storedConsent($this))->toBeNull();
});

it('skips the consent screen once the tokens it led to have expired', function (): void {
    $this->authorizeAndApprove($this->user, $this->client);

    AccessToken::query()->update(['expires_at' => now()->subHour()]);

    authorizeExpectingDecision($this)->assertRedirect();
});

it('keeps the consent when the tokens are revoked', function (): void {
    $result = $this->authorizeAndApprove($this->user, $this->client);

    app(AccessTokenRevoker::class)->revoke((string) parseAccessToken($result->accessToken)->claims()->get('jti'));

    expect(AccessToken::query()->whereNull('revoked_at')->exists())->toBeFalse();

    authorizeExpectingDecision($this)->assertRedirect();
});

it('shows the consent screen again after the consent was withdrawn', function (): void {
    $this->authorizeAndApprove($this->user, $this->client);

    app(ConsentRepository::class)->revoke((string) $this->user->id, $this->client->id);

    authorizeExpectingDecision($this)->assertOk();
    expect(storedConsent($this)?->revoked_at)->not->toBeNull();
});

it('re-activates a withdrawn consent on the next approval', function (): void {
    $this->authorizeAndApprove($this->user, $this->client);
    app(ConsentRepository::class)->revoke((string) $this->user->id, $this->client->id);

    $this->authorizeAndApprove($this->user, $this->client);

    expect(Consent::query()->count())->toBe(1)
        ->and(storedConsent($this)?->revoked_at)->toBeNull();
});

it('asks again for a scope the consent does not cover and merges it in', function (): void {
    $this->authorizeAndApprove($this->user, $this->client);

    authorizeExpectingDecision($this, 'openid email')->assertOk();

    $this->authorizeAndApprove($this->user, $this->client, 'openid email');

    expect(storedConsent($this)?->scopes)->toBe(['openid', 'email']);

    authorizeExpectingDecision($this, 'email')->assertRedirect();
    authorizeExpectingDecision($this, 'openid')->assertRedirect();
});

it('always shows the screen for prompt=consent', function (): void {
    $this->authorizeAndApprove($this->user, $this->client);

    $this->actingAsIdentity($this->user, authTime: time() - 60)
        ->get(route('oidc.authorize').'?'.http_build_query([
            'client_id' => $this->client->client_id,
            'redirect_uri' => 'https://rp.test/callback',
            'response_type' => 'code',
            'scope' => 'openid',
            'state' => 'st4te',
            'prompt' => 'consent',
            'code_challenge' => PkcePair::generate()->challenge,
            'code_challenge_method' => 'S256',
        ]))
        ->assertOk();
});

it('keeps consents per user', function (): void {
    $this->authorizeAndApprove($this->user, $this->client);

    $this->user = User::create(['name' => 'N', 'email' => 'n@example.com', 'email_verified_at' => now(), 'password' => 'x']);

    authorizeExpectingDecision($this)->assertOk();
});

it('grants through the store idempotently', function (): void {
    $store = app(ConsentStore::class);
    $userId = (string) $this->user->id;
    $clientKey = (string) $this->client->getKey();

    $realm = [realmResource()];

    $store->grant($userId, $this->client->snapshot(), ['openid'], $realm);
    $store->grant($userId, $this->client->snapshot(), ['openid', 'profile'], $realm);

    expect(Consent::query()->count())->toBe(1)
        ->and($store->covers($userId, $clientKey, ['profile', 'openid'], $realm))->toBeTrue()
        ->and($store->covers($userId, $clientKey, ['email'], $realm))->toBeFalse()
        ->and($store->covers($userId, $clientKey, [], $realm))->toBeTrue()
        ->and($store->covers($userId, $clientKey, [], ['https://other.test']))->toBeFalse()
        ->and($store->covers($userId, $clientKey, [], []))->toBeFalse()
        ->and($store->covers($userId, (string) Str::uuid(), [], $realm))->toBeFalse();
});

function fakeConsentViewListingScopes(): void
{
    fakeConsentViewUsing(fn (array $parameters) => response()->json([
        'authToken' => $parameters['authToken'],
        'scopes' => array_map(fn (Scope $scope): string => $scope->id, $parameters['scopes']),
    ]));
}

it('shows the client default scopes on the consent screen even when not requested', function (): void {
    $this->client->forceFill(['default_scopes' => ['email']])->save();
    fakeConsentViewListingScopes();

    authorizeExpectingDecision($this)->assertOk()->assertJson(['scopes' => ['openid', 'email']]);
});

it('stores the client default scopes in the consent and skips the screen once they are covered', function (): void {
    $this->client->forceFill(['default_scopes' => ['email']])->save();

    $this->authorizeAndApprove($this->user, $this->client);

    expect(storedConsent($this)?->scopes)->toBe(['openid', 'email']);

    authorizeExpectingDecision($this)->assertRedirect();
    authorizeExpectingDecision($this, 'openid email')->assertRedirect();
});

it('never shows a hidden scope on the consent screen while still granting it', function (): void {
    app()->bind(ScopeRepository::class, fn (): ScopeRepository => new class(app(), app(RealmResolver::class), app(RealmAudiences::class)) extends ConfiguredScopeRepository
    {
        public function all(array $audiences = []): Collection
        {
            return parent::all($audiences)->push(new Scope('internal', 'Internal', hidden: true));
        }
    });

    $this->client->forceFill(['default_scopes' => ['internal']])->save();
    fakeConsentViewListingScopes();

    authorizeExpectingDecision($this)->assertOk()->assertJson(['scopes' => ['openid']]);

    $result = $this->authorizeAndApprove($this->user, $this->client);

    expect($result->response->json('scope'))->toBe('openid internal')
        ->and(storedConsent($this)?->scopes)->toBe(['openid', 'internal']);
});
