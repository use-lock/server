<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\Events;

use Lock\Server\Shared\Audit\AuditEvent;
use Lock\Server\Shared\Audit\AuditEventType;
use Lock\Server\Shared\Audit\AuditRecord;

final class LoggedOut implements AuditEvent
{
    public AuditEventType $type { get => AuditEventType::LoggedOut; }

    public function __construct(public readonly string $userId) {}

    public function auditRecord(): AuditRecord
    {
        return new AuditRecord(
            type: $this->type,
            userId: $this->userId,
        );
    }
}
