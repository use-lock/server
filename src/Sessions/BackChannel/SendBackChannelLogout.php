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

    public function __construct(public readonly string $participantId, public readonly string $realm) {}

    public function handle(LogoutTokenBuilder $builder, Clients $clients, BackChannelLogoutNotifier $notifier, PublicHttpEndpoint $endpoints): void
    {
        CurrentRealm::runAs($this->realm, function () use ($builder, $clients, $notifier, $endpoints): void {
            $participant = SessionParticipant::query()->whereNull('logout_status')->find($this->participantId);
            $session = $participant instanceof SessionParticipant
                ? OidcSession::query()->inRealm($this->realm)->find($participant->session_id)
                : null;

            if (! $session instanceof OidcSession || $session->isActive()) {
                return;
            }

            $client = $clients->findByKey($participant->client_id, $this->realm);
            $uri = $client?->backchannelLogoutUri;
            $status = 'skipped';

            if ($client instanceof Client && is_string($uri) && $uri !== '') {
                $status = 'failed';

                if (! $session->logoutRetryExpired()) {
                    try {
                        $request = $endpoints->request($uri);
                    } catch (InvalidArgumentException) {
                        $request = null;
                    }

                    if ($request instanceof PendingRequest) {
                        $request->asForm()->withoutRedirecting()->connectTimeout(5)->timeout(10)
                            ->post($uri, ['logout_token' => $builder->build($session, $client->clientId)])
                            ->throwUnlessStatus(fn (int $status): bool => $status >= 200 && $status < 300);
                        $status = 'delivered';
                    }
                }
            }

            SessionParticipant::query()->whereKey($participant->id)->whereNull('logout_status')->update(['logout_status' => $status]);
            $notifier->finish($session->id);
        });
    }
}
