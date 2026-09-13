<?php

declare(strict_types=1);

namespace Lock\Server\Sessions\BackChannel;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Facades\Bus;
use Illuminate\Support\Facades\DB;
use Lock\Server\Sessions\Models\OidcSession;
use Lock\Server\Sessions\Models\SessionParticipant;
use Lock\Server\Shared\Clients\Clients;
use Lock\Server\Shared\Realms\CurrentRealm;
use Lock\Server\Shared\Sessions\SessionEnded;
use Throwable;

class BackChannelLogoutNotifier
{
    public function __construct(private readonly Clients $clients) {}

    public function handle(SessionEnded $event): void
    {
        try {
            $this->notify($event->sid);
        } catch (Throwable $exception) {
            report($exception);
        }
    }

    public function notify(string $sid): void
    {
        $session = OidcSession::query()->find($sid);

        if (! $session instanceof OidcSession || $session->isActive() || $session->logout_finished_at !== null) {
            return;
        }

        $pending = SessionParticipant::query()->where('session_id', $sid)->whereNull('logout_status');
        $clientKeys = $this->clients->logoutClientKeys((clone $pending)->pluck('client_id')->all(), $session->realm);
        (clone $pending)->whereNotIn('client_id', $clientKeys)->update(['logout_status' => 'skipped']);

        if ($session->logoutRetryExpired()) {
            $pending->update(['logout_status' => 'failed']);
        } else {
            $pending->where(fn (Builder $query): Builder => $query->whereNull('logout_attempted_at')
                ->orWhere('logout_attempted_at', '<=', now()->subMinutes(5)));

            $pending->eachById(function (SessionParticipant $participant) use ($pending, $session): void {
                if ((clone $pending)->whereKey($participant->id)->update(['logout_attempted_at' => now()]) === 0) {
                    return;
                }

                DB::afterCommit(function () use ($participant, $session): void {
                    try {
                        CurrentRealm::runAs($session->realm, fn () => Bus::dispatch(
                            new SendBackChannelLogout($participant->id, $session->realm),
                        ));
                    } catch (Throwable $exception) {
                        report($exception);
                    }
                });
            });
        }

        $this->finish($sid);
    }

    public function finish(string $sid): void
    {
        if (! SessionParticipant::query()->where('session_id', $sid)->whereNull('logout_status')->exists()) {
            OidcSession::query()->whereKey($sid)->whereNull('logout_finished_at')->update(['logout_finished_at' => now()]);
        }
    }
}
