<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\Events;

use Lock\Server\Shared\Audit\AuditEvent;
use Lock\Server\Shared\Audit\AuditEventType;
use Lock\Server\Shared\Audit\AuditRecord;

final class LoginFailed implements AuditEvent
{
    public AuditEventType $type { get => AuditEventType::LoginFailed; }

    public function __construct(
        public readonly string $method,
        public readonly string $reason,
        public readonly ?string $userId = null,
        public readonly ?string $username = null,
        public readonly ?string $denyReason = null,
    ) {}

    public function auditRecord(): AuditRecord
    {
        return new AuditRecord(
            type: $this->type,
            userId: $this->userId,
            context: [
                'method' => $this->method,
                'username' => $this->username,
                'reason' => $this->reason,
                'deny_reason' => $this->denyReason,
            ],
            failure: true,
        );
    }
}
