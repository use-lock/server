<?php

declare(strict_types=1);

namespace Lock\Server\Credentials\Events;

use Illuminate\Contracts\Events\ShouldDispatchAfterCommit;
use Lock\Server\Shared\Audit\AuditEvent;
use Lock\Server\Shared\Audit\AuditEventType;
use Lock\Server\Shared\Audit\AuditRecord;

final class FactorRevoked implements AuditEvent, ShouldDispatchAfterCommit
{
    public AuditEventType $type { get => AuditEventType::FactorRevoked; }

    public function __construct(
        public readonly string $userId,
        public readonly string $factor,
        public readonly string $enrollmentId,
        public readonly string $realm,
    ) {}

    public function auditRecord(): AuditRecord
    {
        return new AuditRecord(
            type: $this->type,
            userId: $this->userId,
            context: [
                'factor' => $this->factor,
                'enrollment_id' => $this->enrollmentId,
            ],
            realm: $this->realm,
        );
    }
}
