<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Bus;
use Illuminate\Support\Facades\Http;
use Lock\Server\Clients\Models\Client;
use Lock\Server\Sessions\BackChannel\SendBackChannelLogout;
use Lock\Server\Sessions\Models\OidcSession;
use Lock\Server\Sessions\Models\SessionParticipant;
use Lock\Server\Shared\Http\DnsResolver;
use Lock\Server\Shared\Realms\CurrentRealm;

it('recovers pending recipients across realms after their dispatch lease expires', function (string $ended): void {
    $this->mock(DnsResolver::class)->shouldReceive('addresses')->once()->with('a.test')->andReturn(['1.1.1.1']);
    Bus::fake();
    Http::fake();
    [$session, $participant] = CurrentRealm::runAs('acme', function () use ($ended): array {
        generateRealmSigningKey();
        $session = OidcSession::factory()->create([$ended => now()->subMinute()]);
        $participant = SessionParticipant::factory()->inSession($session)
            ->forClient(Client::factory()->create(['backchannel_logout_uri' => 'https://a.test/bclo']))->create();

        return [$session, $participant];
    });

    $this->artisan('oidc:dispatch-expired-session-logouts')->assertSuccessful();
    $this->artisan('oidc:dispatch-expired-session-logouts')->assertSuccessful();

    Bus::assertDispatchedTimes(SendBackChannelLogout::class, 1);
    expect($session->refresh()->logout_finished_at)->toBeNull();

    $this->travel(6)->minutes();
    $this->artisan('oidc:dispatch-expired-session-logouts')->assertSuccessful();
    Bus::assertDispatchedTimes(SendBackChannelLogout::class, 2);
    app()->call([Bus::dispatched(SendBackChannelLogout::class)->first(), 'handle']);
    $this->artisan('oidc:dispatch-expired-session-logouts')->assertSuccessful();

    Bus::assertDispatchedTimes(SendBackChannelLogout::class, 2);
    expect($participant->refresh()->logout_status)->toBe('delivered')
        ->and($session->refresh()->logout_finished_at)->not->toBeNull();
})->with(['expires_at', 'revoked_at']);

it('records terminal failures at the retry deadline before the pruning grace starts', function (): void {
    Bus::fake();
    config(['oidc.session.logout_retry_lifetime' => 3600, 'oidc.pruning.sessions' => 3600]);
    $session = OidcSession::factory()->create(['revoked_at' => now()->subHours(2), 'expires_at' => now()->addMonth()]);
    $pending = SessionParticipant::factory()->inSession($session)
        ->forClient(Client::factory()->create(['backchannel_logout_uri' => 'https://a.test/bclo']))->create();
    $skipped = SessionParticipant::factory()->inSession($session)->create();

    $this->artisan('oidc:prune')->assertSuccessful();
    $this->assertModelExists($pending);
    $this->artisan('oidc:dispatch-expired-session-logouts')->assertSuccessful();
    $this->artisan('oidc:prune')->assertSuccessful();

    Bus::assertNothingDispatched();
    expect($pending->refresh()->logout_status)->toBe('failed')
        ->and($skipped->refresh()->logout_status)->toBe('skipped')
        ->and($session->refresh()->logout_finished_at)->not->toBeNull();

    $this->travel(2)->hours();
    $this->artisan('oidc:prune')->assertSuccessful();

    $this->assertModelMissing($session);
    $this->assertModelMissing($pending);
});
