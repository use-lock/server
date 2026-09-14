<?php

declare(strict_types=1);

namespace Lock\Server\Sessions\BackChannel;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Queue\InteractsWithQueue;
use InvalidArgumentException;
use Lock\Server\Sessions\LogoutTokenBuilder;
use Lock\Server\Sessions\Models\OidcSession;
use Lock\Server\Sessions\Models\SessionParticipant;
use Lock\Server\Shared\Clients\Client;
use Lock\Server\Shared\Clients\Clients;
use Lock\Server\Shared\Http\PublicHttpEndpoint;
use Lock\Server\Shared\Realms\CurrentRealm;

class SendBackChannelLogout implements ShouldQueue
{
    use Dispatchable;
    use InteractsWithQueue;
    use Queueable;

    public int $tries = 3;

    /** @var list<int> */
    public array $backoff = [10, 60];

    public int $timeout = 30;

    public function __construct(
        public readonly string $participantId,
        public readonly string $realm,
        public readonly ?LogoutDelivery $delivery = null,
    ) {}

    public function handle(LogoutTokenBuilder $builder, Clients $clients, BackChannelLogoutNotifier $notifier, PublicHttpEndpoint $endpoints): void
    {
        CurrentRealm::runAs($this->realm, function () use ($builder, $clients, $notifier, $endpoints): void {
            $participant = SessionParticipant::query()->find($this->participantId);

            if ($participant?->logout_status !== null) {
                return;
            }

            $session = $participant instanceof SessionParticipant
                ? OidcSession::query()->inRealm($this->realm)->find($participant->session_id)
                : null;

            if ($session?->isActive()) {
                return;
            }

            $client = $participant instanceof SessionParticipant
                ? $clients->findByKey($participant->client_id, $this->realm)
                : null;
            $delivery = $session instanceof OidcSession
                ? ($client instanceof Client ? LogoutDelivery::from($session, $client) : null)
                : $this->delivery;
            $uri = $delivery?->uri;
            $status = 'skipped';

            if ($delivery instanceof LogoutDelivery && is_string($uri) && $uri !== '') {
                $status = 'failed';

                if (! ($delivery->retryUntil?->isPast() ?? false)) {
                    try {
                        $request = $endpoints->request($uri);
                    } catch (InvalidArgumentException) {
                        $request = null;
                    }

                    if ($request instanceof PendingRequest) {
                        $request->asForm()->withoutRedirecting()->connectTimeout(5)->timeout(10)
                            ->post($uri, ['logout_token' => $builder->buildFor($delivery->sid, $delivery->userId, $delivery->clientId)])
                            ->throwUnlessStatus(fn (int $status): bool => $status >= 200 && $status < 300);
                        $status = 'delivered';
                    }
                }
            }

            if ($participant instanceof SessionParticipant && $session instanceof OidcSession) {
                SessionParticipant::query()->whereKey($participant->id)->whereNull('logout_status')->update(['logout_status' => $status]);
                $notifier->finish($session->id);
            }
        });
    }
}
