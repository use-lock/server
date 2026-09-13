<?php

declare(strict_types=1);

namespace Lock\Server\Credentials\Events;

use Lock\Server\Shared\Audit\AuditEvent;
use Lock\Server\Shared\Audit\AuditEventType;
use Lock\Server\Shared\Audit\AuditRecord;

final class MfaChallengeSucceeded implements AuditEvent
{
    public AuditEventType $type { get => AuditEventType::MfaChallengeSucceeded; }

    public function __construct(
        public readonly string $userId,
        public readonly string $factor,
    ) {}

    public function auditRecord(): AuditRecord
    {
        return new AuditRecord(
            type: $this->type,
            userId: $this->userId,
            context: [
                'factor' => $this->factor,
            ],
        );
    }
}
