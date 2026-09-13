<?php

declare(strict_types=1);

use Lock\Server\Clients\Models\Client;
use Lock\Server\Sessions\Models\OidcSession;
use Lock\Server\Sessions\Models\SessionParticipant;
use Lock\Server\Sessions\OidcSessionRepository;
use Workbench\App\Models\User;

it('creates a session, records participants idempotently, and revokes', function (): void {
    config(['oidc.session.absolute_lifetime' => 3600]);
    $registry = app(OidcSessionRepository::class);

    $user = User::factory()->create();

    $sid = $registry->start((string) $user->getKey());
    $session = $registry->find($sid);
    expect($session)->toBeInstanceOf(OidcSession::class)
        ->and($session->user_id)->toBe((string) $user->getKey())
        ->and($session->expires_at->isFuture())->toBeTrue()
        ->and($session->revoked_at)->toBeNull();

    $first = (string) Client::factory()->create()->getKey();
    $second = (string) Client::factory()->create()->getKey();

    $registry->recordParticipant($sid, $first);
    $registry->recordParticipant($sid, $first);
    $registry->recordParticipant($sid, $second);
    expect(SessionParticipant::query()->where('session_id', $sid)->pluck('client_id')->all())->toEqualCanonicalizing([$first, $second]);

    $registry->revoke($sid);
    expect($registry->find($sid)->revoked_at)->not->toBeNull();

});
