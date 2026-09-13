<?php

declare(strict_types=1);

/**
 * OpenID Connect Core 1.0 §3.1.2.1 (prompt=none, prompt=consent)
 */

use Illuminate\Foundation\Http\Middleware\ValidateCsrfToken;
use Illuminate\Support\Facades\Hash;
use Illuminate\Testing\TestResponse;
use Lock\Server\Clients\ClientRepository;
use Lock\Server\Support\Testing\InteractsWithOidc;
use Symfony\Component\HttpFoundation\Response;
use Workbench\App\Models\User;

uses(InteractsWithOidc::class);

beforeEach(function (): void {
    $this->withoutMiddleware(ValidateCsrfToken::class);
    fakeConsentViewUsing(fn (array $parameters) => response()->json(['authToken' => $parameters['authToken']]));

    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'email_verified_at' => now(), 'password' => Hash::make('password')]);
    $this->client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Self RP', ['https://rp.test/callback']);
});

/**
 * @param  array<string, string>  $overrides
 * @return TestResponse<Response>
 */
function selfSsoAuthorize(mixed $test, array $overrides = []): TestResponse
{
    return $test->get('/oauth/authorize?'.http_build_query([
        'client_id' => (string) $test->client->id,
        'redirect_uri' => 'https://rp.test/callback',
        'response_type' => 'code',
        'scope' => 'openid email',
        'state' => 'st4te',
        'nonce' => 'n0nce',
        'code_challenge' => $test->pkce()->challenge,
        'code_challenge_method' => 'S256',
        ...$overrides,
    ]));
}

it('returns a credential login to the pending authorization request without creating a web session', function (): void {
    config(['oidc.login.route' => 'identity.login']);

    selfSsoAuthorize($this)->assertRedirect('/auth/login');

    $response = $this->post(route('identity.login.store'), ['email' => 'm@example.com', 'password' => 'password'])->assertRedirect();

    expect($response->headers->get('Location'))->toContain('/oauth/authorize?')
        ->and(auth('identity')->check())->toBeTrue()
        ->and(auth('web')->guest())->toBeTrue();
});

it('auto-approves a trusted client, also for prompt=consent and prompt=none', function (array $overrides): void {
    config(['oidc.clients.trusted' => [$this->client->id]]);
    $this->actingAsIdentity($this->user);

    $response = selfSsoAuthorize($this, $overrides)->assertRedirect();

    expect($response->headers->get('Location'))->toStartWith('https://rp.test/callback?')->toContain('code=');
})->with([
    'plain' => [[]],
    'prompt=consent' => [['prompt' => 'consent']],
    'prompt=none' => [['prompt' => 'none']],
]);

it('lets the first-party trusted flag decide over the trusted list', function (bool $firstPartyTrusted, array $trustedList): void {
    config([
        'oidc.clients.first_party' => ['client_id' => (string) $this->client->id, 'trusted' => $firstPartyTrusted],
        'oidc.clients.trusted' => array_map(fn (string $id): string => $id === '{client}' ? (string) $this->client->id : $id, $trustedList),
    ]);
    $this->actingAsIdentity($this->user);

    $response = selfSsoAuthorize($this);

    if ($firstPartyTrusted) {
        expect($response->assertRedirect()->headers->get('Location'))->toStartWith('https://rp.test/callback?')->toContain('code=');
    } else {
        $response->assertOk()->assertJsonStructure(['authToken']);
    }
})->with([
    'untrusted first party listed as trusted' => [false, ['{client}']],
    'trusted first party without listing' => [true, []],
]);
