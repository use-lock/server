<?php

declare(strict_types=1);

namespace Lock\Server\Clients\Events;

use Illuminate\Contracts\Events\ShouldDispatchAfterCommit;
use Lock\Server\Shared\Audit\AuditEvent;
use Lock\Server\Shared\Audit\AuditEventType;
use Lock\Server\Shared\Audit\AuditRecord;

final class ClientProvisioned implements AuditEvent, ShouldDispatchAfterCommit
{
    public AuditEventType $type { get => AuditEventType::ClientProvisioned; }

    public function __construct(
        public readonly string $clientId,
        public readonly bool $created,
        public readonly bool $secretRotated,
        public readonly string $realm,
    ) {}

    public function auditRecord(): AuditRecord
    {
        return new AuditRecord(
            type: $this->type,
            clientId: $this->clientId,
            context: [
                'created' => $this->created,
                'secret_rotated' => $this->secretRotated,
            ],
            realm: $this->realm,
        );
    }
}
