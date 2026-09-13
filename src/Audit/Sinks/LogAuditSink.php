<?php

declare(strict_types=1);

namespace Lock\Server\Audit\Sinks;

use DateTimeInterface;
use Illuminate\Support\Facades\Log;
use Lock\Server\Audit\Contracts\AuditSink;
use Lock\Server\Shared\Audit\AuditRecord;

final class LogAuditSink implements AuditSink
{
    public function record(AuditRecord $record): void
    {
        $channel = config('oidc.audit.log_channel');

        Log::channel(is_string($channel) && $channel !== '' ? $channel : null)->log(
            $record->failure ? 'warning' : 'info',
            'oidc: audit '.$record->type->value,
            [
                ...array_filter([
                    'user_id' => $record->userId,
                    'client_id' => $record->clientId,
                    'sid' => $record->sid,
                    'ip' => $record->ip,
                    'user_agent' => $record->userAgent,
                ], static fn (?string $value): bool => $value !== null),
                'occurred_at' => $record->occurredAt->format(DateTimeInterface::ATOM),
                ...$record->context,
            ],
        );
    }
}
