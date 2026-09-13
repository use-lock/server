<?php

declare(strict_types=1);

/**
 * OpenID Connect RP-Initiated Logout 1.0 §2 (id_token_hint, client_id, post_logout_redirect_uri, state),
 * §4 (security/CSRF), §6 (confirmation)
 */

use Illuminate\Foundation\Http\Middleware\ValidateCsrfToken;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Lock\Server\Clients\ClientRepository;
use Lock\Server\Protocol\LogoutConfirmation;
use Lock\Server\Protocol\Ui\Views\LogoutConfirmationView;
use Lock\Server\Protocol\Ui\Views\LogoutPrompt;
use Lock\Server\Support\Testing\FakesAuthViews;
use Lock\Server\Tests\FeatureTestCase;
use Lock\Server\Tokens\IdTokenBuilder;
use Lock\Server\Tokens\IdTokenRequest;
use Workbench\App\Models\User;

uses(FakesAuthViews::class);

beforeEach(function (): void {
    $this->fakeAuthViews();

    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    $this->client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/callback']);
    $this->client->forceFill(['post_logout_redirect_uris' => ['https://rp.test/logged-out']])->save();
});

function issueIdToken(FeatureTestCase $test, ?User $subject = null): string
{
    $user = $subject ?? $test->user;

    return app(IdTokenBuilder::class)->build(new IdTokenRequest(
        userId: (string) $user->id,
        clientId: (string) $test->client->id,
        scopes: ['openid'],
        accessToken: 'access-token-jwt',
    ));
}

it('logs out and redirects to a registered post_logout_redirect_uri', function (): void {
    $response = $this->actingAs($this->user, 'identity')->get('/oauth/logout?'.http_build_query([
        'id_token_hint' => issueIdToken($this),
        'post_logout_redirect_uri' => 'https://rp.test/logged-out',
        'state' => 'xyz',
    ]));

    $response->assertRedirect('https://rp.test/logged-out?state=xyz');
    expect(auth('identity')->guest())->toBeTrue();
});

it('answers an Inertia logout request with a 409 + X-Inertia-Location instead of a redirect', function (): void {
    $response = $this->actingAs($this->user, 'identity')->get('/oauth/logout?'.http_build_query([
        'id_token_hint' => issueIdToken($this),
        'post_logout_redirect_uri' => 'https://rp.test/logged-out',
        'state' => 'xyz',
    ]), ['X-Inertia' => 'true']);

    $response->assertStatus(409);
    expect($response->headers->get('X-Inertia-Location'))->toBe('https://rp.test/logged-out?state=xyz');
    expect(auth('identity')->guest())->toBeTrue();
});

it('falls back to the configured redirect for unregistered uris', function (): void {
    $this->actingAs($this->user, 'identity')->get('/oauth/logout?'.http_build_query([
        'id_token_hint' => issueIdToken($this),
        'post_logout_redirect_uri' => 'https://evil.test/phish',
    ]))->assertRedirect('/');

    expect(auth('identity')->guest())->toBeTrue();
});

it('does not log out on a GET without a valid id_token_hint', function (): void {
    $this->actingAs($this->user, 'identity')->get('/oauth/logout?'.http_build_query([
        'id_token_hint' => 'garbage',
        'post_logout_redirect_uri' => 'https://rp.test/logged-out',
    ]))->assertOk()->assertJsonPath('view', 'logout-confirmation');

    expect(auth('identity')->check())->toBeTrue();
});

it('does not log out on a parameterless GET', function (): void {
    $this->actingAs($this->user, 'identity')->get('/oauth/logout')->assertOk()->assertJsonPath('view', 'logout-confirmation');

    expect(auth('identity')->check())->toBeTrue();
});

it('logs out on a POST without a valid id_token_hint', function (): void {
    $this->withoutMiddleware(ValidateCsrfToken::class)
        ->actingAs($this->user, 'identity')
        ->post('/oauth/logout')
        ->assertRedirect('/');

    expect(auth('identity')->guest())->toBeTrue();
});

it('logs out on a GET with a valid id_token_hint', function (): void {
    $this->actingAs($this->user, 'identity')->get('/oauth/logout?'.http_build_query([
        'id_token_hint' => issueIdToken($this),
    ]))->assertRedirect('/');

    expect(auth('identity')->guest())->toBeTrue();
});

// §2 — client_id identifies the RP when no id_token_hint is given
it('honours a post_logout_redirect_uri registered on the client named by client_id', function (): void {
    $this->withoutMiddleware(ValidateCsrfToken::class)
        ->actingAs($this->user, 'identity')
        ->post('/oauth/logout', [
            'client_id' => $this->client->client_id,
            'post_logout_redirect_uri' => 'https://rp.test/logged-out',
            'state' => 'xyz',
        ])
        ->assertRedirect('https://rp.test/logged-out?state=xyz');

    expect(auth('identity')->guest())->toBeTrue();
});

it('falls back to the configured redirect when client_id names a client the uri is not registered on', function (): void {
    $other = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Other', ['https://other.test/cb']);

    $this->withoutMiddleware(ValidateCsrfToken::class)
        ->actingAs($this->user, 'identity')
        ->post('/oauth/logout', [
            'client_id' => $other->client_id,
            'post_logout_redirect_uri' => 'https://rp.test/logged-out',
        ])
        ->assertRedirect('/');

    expect(auth('identity')->guest())->toBeTrue();
});

it('sends a signed-out browser on to the uri registered on the client named by client_id', function (): void {
    $this->get('/oauth/logout?'.http_build_query([
        'client_id' => $this->client->client_id,
        'post_logout_redirect_uri' => 'https://rp.test/logged-out',
        'state' => 'xyz',
    ]))->assertRedirect('https://rp.test/logged-out?state=xyz');
});

// §2 — client_id and id_token_hint must agree
it('rejects a client_id that is not in the audience of the id_token_hint', function (): void {
    $other = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Other', ['https://other.test/cb']);

    $this->actingAs($this->user, 'identity')->get('/oauth/logout?'.http_build_query([
        'id_token_hint' => issueIdToken($this),
        'client_id' => $other->client_id,
        'post_logout_redirect_uri' => 'https://rp.test/logged-out',
    ]))->assertStatus(400)->assertJsonPath('error', 'invalid_request');

    expect(auth('identity')->check())->toBeTrue();
});

it('accepts a client_id matching the hint audience and ignores logout_hint and ui_locales', function (): void {
    $this->actingAs($this->user, 'identity')->get('/oauth/logout?'.http_build_query([
        'id_token_hint' => issueIdToken($this),
        'client_id' => $this->client->client_id,
        'post_logout_redirect_uri' => 'https://rp.test/logged-out',
        'logout_hint' => 'm@example.com',
        'ui_locales' => 'de-DE en',
    ]))->assertRedirect('https://rp.test/logged-out');

    expect(auth('identity')->guest())->toBeTrue();
});

function bindLogoutConfirmationView(): void
{
    app()->instance(LogoutConfirmationView::class, new class implements LogoutConfirmationView
    {
        public function respond(LogoutPrompt $prompt, Request $request): JsonResponse
        {
            return response()->json([
                'user' => (string) $prompt->user->getAuthIdentifier(),
                'client' => $prompt->client?->clientId,
                'post_logout_redirect_uri' => $prompt->postLogoutRedirectUri,
                'state' => $prompt->state,
                'confirmation' => $prompt->confirmationToken,
            ]);
        }
    });
}

// §6 — a GET without a verifiable hint asks the signed-in user; the confirmed POST performs the logout
it('renders the confirmation view for a GET without a verifiable hint and logs out on the confirmed POST', function (): void {
    bindLogoutConfirmationView();

    $prompt = $this->actingAs($this->user, 'identity')->get('/oauth/logout?'.http_build_query([
        'client_id' => $this->client->client_id,
        'post_logout_redirect_uri' => 'https://rp.test/logged-out',
        'state' => 'xyz',
    ]))->assertOk();

    expect(auth('identity')->check())->toBeTrue()
        ->and($prompt->json('user'))->toBe((string) $this->user->id)
        ->and($prompt->json('client'))->toBe($this->client->client_id)
        ->and($prompt->json('post_logout_redirect_uri'))->toBe('https://rp.test/logged-out')
        ->and($prompt->json('state'))->toBe('xyz')
        ->and($prompt->json('confirmation'))->toBeString();

    $this->withoutMiddleware(ValidateCsrfToken::class)
        ->post('/oauth/logout', ['logout_confirmation' => $prompt->json('confirmation')])
        ->assertRedirect('https://rp.test/logged-out?state=xyz');

    expect(auth('identity')->guest())->toBeTrue();
});

it('prompts the signed-in user instead of trusting a hint issued to somebody else', function (): void {
    bindLogoutConfirmationView();
    $other = User::create(['name' => 'O', 'email' => 'o@example.com', 'password' => 'x']);

    $this->actingAs($this->user, 'identity')->get('/oauth/logout?'.http_build_query([
        'id_token_hint' => issueIdToken($this, $other),
    ]))->assertOk()->assertJsonPath('user', (string) $this->user->id)->assertJsonPath('post_logout_redirect_uri', null);

    expect(auth('identity')->check())->toBeTrue();
});

it('rejects a confirmation issued to another user or tampered with', function (): void {
    $other = User::create(['name' => 'O', 'email' => 'o@example.com', 'password' => 'x']);
    $foreign = app(LogoutConfirmation::class)->issue($other, 'https://rp.test/logged-out', null);

    $this->withoutMiddleware(ValidateCsrfToken::class)->actingAs($this->user, 'identity');

    $this->post('/oauth/logout', ['logout_confirmation' => $foreign])
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_request');
    $this->post('/oauth/logout', ['logout_confirmation' => 'garbage'])
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_request');

    expect(auth('identity')->check())->toBeTrue();
});

it('rejects an expired confirmation', function (): void {
    $token = app(LogoutConfirmation::class)->issue($this->user, null, null);

    $this->travel(11)->minutes();

    $this->withoutMiddleware(ValidateCsrfToken::class)
        ->actingAs($this->user, 'identity')
        ->post('/oauth/logout', ['logout_confirmation' => $token])
        ->assertStatus(400);

    expect(auth('identity')->check())->toBeTrue();
});
