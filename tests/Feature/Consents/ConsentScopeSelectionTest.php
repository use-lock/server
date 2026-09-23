<?php

declare(strict_types=1);

/**
 * RFC 6749 §3.3 — the authorization server may grant fewer scopes than requested
 */

use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Foundation\Http\Middleware\ValidateCsrfToken;
use Illuminate\Testing\TestResponse;
use Lock\Server\Clients\ClientRepository;
use Lock\Server\Consents\ConsentRepository;
use Lock\Server\Shared\Clients\Client;
use Lock\Server\Shared\Scopes\Scope;
use Lock\Server\Shared\Scopes\ScopeParameterPolicy;
use Lock\Server\Support\Testing\InteractsWithOidc;
use Lock\Server\Support\Testing\PkcePair;
use Lock\Server\Tests\FeatureTestCase;
use Symfony\Component\HttpFoundation\Response;
use Workbench\App\Models\User;

uses(InteractsWithOidc::class);

beforeEach(function (): void {
    $this->withoutMiddleware([ValidateCsrfToken::class, PreventRequestForgery::class]);
    config(['oidc.scopes' => ['organization:{organization}' => 'Act within organization {organization}']]);
    app()->instance(ScopeParameterPolicy::class, new readonly class implements ScopeParameterPolicy
    {
        public function allows(Scope $scope, string $grantType, ?Client $client, ?string $userIdentifier, array $audiences): bool
        {
            return $scope->parameter === 'acme';
        }
    });
    fakeConsentViewUsing(fn (array $parameters) => response()->json([
        'authToken' => $parameters['authToken'],
        'scopes' => array_map(fn (Scope $scope): string => $scope->id, $parameters['scopes']),
    ]));

    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'email_verified_at' => now(), 'password' => 'x']);
    $this->client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/callback']);
    $this->client->forceFill(['default_scopes' => [], 'optional_scopes' => ['openid', 'email', 'organization:{organization}']])->save();
    $this->actingAsIdentity($this->user);
});

/**
 * @param  array<string, string>  $params
 * @return TestResponse<Response>
 */
function requestConsent(FeatureTestCase $test, string $scopes, array $params = []): TestResponse
{
    return $test->get(route('oidc.authorize').'?'.http_build_query([
        'client_id' => $test->client->client_id,
        'redirect_uri' => 'https://rp.test/callback',
        'response_type' => 'code',
        'scope' => $scopes,
        'state' => 'st4te',
        'code_challenge' => PkcePair::generate()->challenge,
        'code_challenge_method' => 'S256',
        ...$params,
    ]));
}

/** @return list<string>|null */
function consentedScopes(FeatureTestCase $test): ?array
{
    return app(ConsentRepository::class)->findByKey((string) $test->user->id, $test->client->id, config('app.url'))?->scopes;
}

it('asks a trusted client for consent on an open template', function (): void {
    $this->withFirstPartyClient($this->client);

    expect(requestConsent($this, 'openid organization:{organization}')->assertOk()->json('scopes'))
        ->toBe(['openid', 'organization:{organization}']);
});

it('refuses an open template without interaction', function (): void {
    requestConsent($this, 'openid organization:{organization}', ['prompt' => 'none'])
        ->assertRedirect()
        ->assertRedirectContains('error=consent_required');
});

it('fills an open template with the value the user chose', function (): void {
    $authToken = requestConsent($this, 'openid organization:{organization}')->json('authToken');

    $this->post(route('oidc.approve'), ['auth_token' => $authToken, 'scopes' => ['openid', 'organization:acme']])->assertRedirect();

    expect(consentedScopes($this))->toBe(['openid', 'organization:acme']);
});

it('drops a chosen value the parameter policy refuses', function (): void {
    $authToken = requestConsent($this, 'openid organization:{organization}')->json('authToken');

    $this->post(route('oidc.approve'), ['auth_token' => $authToken, 'scopes' => ['openid', 'organization:globex']])->assertRedirect();

    expect(consentedScopes($this))->toBe(['openid']);
});

it('grants only the requested scopes the user kept', function (): void {
    $authToken = requestConsent($this, 'openid email')->json('authToken');

    $this->post(route('oidc.approve'), ['auth_token' => $authToken, 'scopes' => ['openid', 'profile']])->assertRedirect();

    expect(consentedScopes($this))->toBe(['openid']);
});

it('lets an open template lapse when the approval selects nothing', function (): void {
    $result = $this->authorizeAndApprove($this->user, $this->client, 'openid email organization:{organization}');

    expect($result->response->json('scope'))->toBe('openid email');
});

it('never offers a concrete value the parameter policy refuses', function (): void {
    expect(requestConsent($this, 'openid organization:globex')->assertOk()->json('scopes'))->toBe(['openid']);
});
