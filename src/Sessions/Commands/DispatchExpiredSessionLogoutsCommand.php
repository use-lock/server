<?php

declare(strict_types=1);

namespace Lock\Server\Sessions\Commands;

use Illuminate\Console\Command;
use Illuminate\Database\Eloquent\Builder;
use Lock\Server\Sessions\BackChannel\BackChannelLogoutNotifier;
use Lock\Server\Sessions\Models\OidcSession;

class DispatchExpiredSessionLogoutsCommand extends Command
{
    protected $signature = 'oidc:dispatch-expired-session-logouts';

    protected $description = 'Deliver or retry back-channel logout for expired and revoked sessions.';

    public function handle(BackChannelLogoutNotifier $notifier): int
    {
        $count = 0;

        OidcSession::query()
            ->where(fn (Builder $query): Builder => $query->where('expires_at', '<=', now())->orWhereNotNull('revoked_at'))
            ->whereNull('logout_finished_at')
            ->eachById(function (OidcSession $session) use ($notifier, &$count): void {
                $notifier->notify($session->id);
                $count++;
            });

        $this->info("Processed logout for {$count} ended session(s).");

        return self::SUCCESS;
    }
}
