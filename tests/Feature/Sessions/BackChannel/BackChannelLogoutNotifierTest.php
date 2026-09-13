<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Bus;
use Illuminate\Support\Facades\DB;
use Lock\Server\Clients\Models\Client;
use Lock\Server\Sessions\BackChannel\SendBackChannelLogout;
use Lock\Server\Sessions\Models\OidcSession;
use Lock\Server\Sessions\Models\SessionParticipant;
use Lock\Server\Sessions\OidcSessionRepository;

it('dispatches only recipients with a logout URI after local revocation commits', function (): void {
    Bus::fake();
    $session = OidcSession::factory()->create();
    $recipient = SessionParticipant::factory()->inSession($session)
        ->forClient(Client::factory()->create(['backchannel_logout_uri' => 'https://a.test/bclo']))->create();
    $skipped = SessionParticipant::factory()->inSession($session)->create();

    DB::transaction(function () use ($session): void {
        app(OidcSessionRepository::class)->revoke($session->id);

        expect($session->refresh()->revoked_at)->not->toBeNull();
        Bus::assertNothingDispatched();
    });

    Bus::assertDispatchedTimes(SendBackChannelLogout::class, 1);
    Bus::assertDispatched(SendBackChannelLogout::class, fn (SendBackChannelLogout $job): bool => $job->participantId === $recipient->id);
    expect($recipient->refresh()->logout_status)->toBeNull()
        ->and($skipped->refresh()->logout_status)->toBe('skipped')
        ->and($session->refresh()->logout_finished_at)->toBeNull();
});

it('does not dispatch a logout when local revocation rolls back', function (): void {
    Bus::fake();
    $session = OidcSession::factory()->create();
    SessionParticipant::factory()->inSession($session)
        ->forClient(Client::factory()->create(['backchannel_logout_uri' => 'https://a.test/bclo']))->create();

    try {
        DB::transaction(function () use ($session): void {
            app(OidcSessionRepository::class)->revoke($session->id);

            throw new RuntimeException('rollback');
        });
    } catch (RuntimeException) {
    }

    Bus::assertNothingDispatched();
    expect($session->refresh()->revoked_at)->toBeNull();
});

it('leaves failed queue delivery recoverable without undoing local revocation', function (): void {
    Bus::shouldReceive('dispatch')->once()->andThrow(new RuntimeException('queue unavailable'));
    $session = OidcSession::factory()->create();
    $participant = SessionParticipant::factory()->inSession($session)
        ->forClient(Client::factory()->create(['backchannel_logout_uri' => 'https://a.test/bclo']))->create();

    app(OidcSessionRepository::class)->revoke($session->id);

    expect($session->refresh()->revoked_at)->not->toBeNull()
        ->and($session->logout_finished_at)->toBeNull()
        ->and($participant->refresh()->logout_status)->toBeNull()
        ->and($participant->logout_attempted_at)->not->toBeNull();
});
