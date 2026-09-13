<?php

declare(strict_types=1);

/**
 * OpenID Connect RP-Initiated Logout 1.0 §2 (id_token_hint) + Back-Channel Logout 1.0 §2.1 (sid), §2.6 (fan-out to participants)
 */

use Illuminate\Foundation\Http\Middleware\ValidateCsrfToken;
use Illuminate\Support\Facades\Bus;
use Lock\Server\Clients\ClientRepository;
use Lock\Server\Sessions\BackChannel\SendBackChannelLogout;
use Lock\Server\Sessions\Models\SessionParticipant;
use Lock\Server\Sessions\OidcSessionRepository;
use Lock\Server\Support\Testing\InteractsWithOidc;
use Workbench\App\Models\User;

uses(InteractsWithOidc::class);

beforeEach(function (): void {
    Bus::fake();
    $this->withoutMiddleware(ValidateCsrfToken::class);
    fakeConsentViewUsing(fn (array $parameters) => response()->json(['authToken' => $parameters['authToken']]));

    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'email_verified_at' => now(), 'password' => bcrypt('secret-password')]);
    $this->client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/callback']);
    $this->client->forceFill(['backchannel_logout_uri' => 'https://rp.test/bclo'])->save();
});

it('revokes the session and notifies each participant once on RP-initiated logout', function (): void {
    $sid = app(OidcSessionRepository::class)->start((string) $this->user->id);
    $this->actingAsIdentity($this->user, amr: ['pwd'], authTime: time() - 60)->withSession(['oidc.sid' => $sid]);

    $idToken = $this->authorizeAndApprove($this->user, $this->client, scopes: 'openid')->idToken;
    $this->authorizeAndApprove($this->user, $this->client, scopes: 'openid');

    $this->post('/oauth/logout', ['id_token_hint' => $idToken])->assertRedirect();

    expect(auth('identity')->guest())->toBeTrue()
        ->and(app(OidcSessionRepository::class)->find($sid)->revoked_at)->not->toBeNull();

    Bus::assertDispatchedTimes(SendBackChannelLogout::class, 1);
    Bus::assertDispatched(SendBackChannelLogout::class, fn (SendBackChannelLogout $job): bool => SessionParticipant::query()->find($job->participantId)?->client_id === (string) $this->client->getKey());
});

it('revokes the session started by a credential login when the user logs out', function (): void {
    $this->post(route('identity.login.store'), ['email' => 'm@example.com', 'password' => 'secret-password'])->assertRedirect();
    $sid = session('oidc.sid');

    $this->authorizeAndApprove($this->user, $this->client, scopes: 'openid')->response->assertOk();

    $this->post(route('oidc.logout'))->assertRedirect();

    expect(app(OidcSessionRepository::class)->find($sid)->revoked_at)->not->toBeNull();
    Bus::assertDispatchedTimes(SendBackChannelLogout::class, 1);
});
