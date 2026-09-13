<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\Events;

use Illuminate\Contracts\Events\ShouldDispatchAfterCommit;
use Lock\Server\Shared\Audit\AuditEvent;
use Lock\Server\Shared\Audit\AuditEventType;
use Lock\Server\Shared\Audit\AuditRecord;

final class PasswordChanged implements AuditEvent, ShouldDispatchAfterCommit
{
    public AuditEventType $type { get => AuditEventType::PasswordChanged; }

    public function __construct(public readonly string $userId, public readonly string $realm) {}

    public function auditRecord(): AuditRecord
    {
        return new AuditRecord(
            type: $this->type,
            userId: $this->userId,
            realm: $this->realm,
        );
    }
}
