<?php

declare(strict_types=1);

namespace Lock\Server\Credentials\Events;

use Lock\Server\Shared\Audit\AuditEvent;
use Lock\Server\Shared\Audit\AuditEventType;
use Lock\Server\Shared\Audit\AuditRecord;

final class MfaChallengeFailed implements AuditEvent
{
    public AuditEventType $type { get => AuditEventType::MfaChallengeFailed; }

    public function __construct(
        public readonly string $userId,
        public readonly string $factor,
        public readonly string $reason,
    ) {}

    public function auditRecord(): AuditRecord
    {
        return new AuditRecord(
            type: $this->type,
            userId: $this->userId,
            context: [
                'factor' => $this->factor,
                'reason' => $this->reason,
            ],
            failure: true,
        );
    }
}
