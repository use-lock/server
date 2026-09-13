<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Protocol;

use Lock\Server\Shared\Audit\AuditEvent;
use Lock\Server\Shared\Audit\AuditEventType;
use Lock\Server\Shared\Audit\AuditRecord;

final class ClientAuthenticationFailed implements AuditEvent
{
    public AuditEventType $type { get => AuditEventType::ClientAuthenticationFailed; }

    public function __construct(
        public readonly string $endpoint,
        public readonly string $reason,
        public readonly ?string $clientId = null,
    ) {}

    public function auditRecord(): AuditRecord
    {
        return new AuditRecord(
            type: $this->type,
            clientId: $this->clientId,
            context: [
                'endpoint' => $this->endpoint,
                'reason' => $this->reason,
            ],
            failure: true,
        );
    }
}
