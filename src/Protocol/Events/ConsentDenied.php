<?php

declare(strict_types=1);

namespace Lock\Server\Protocol\Events;

use Lock\Server\Shared\Audit\AuditEvent;
use Lock\Server\Shared\Audit\AuditEventType;
use Lock\Server\Shared\Audit\AuditRecord;

final class ConsentDenied implements AuditEvent
{
    public AuditEventType $type { get => AuditEventType::ConsentDenied; }

    /**
     * @param  list<string>  $scopes
     * @param  list<string>  $resources  the resource identifiers the decision was made for
     */
    public function __construct(
        public readonly array $scopes,
        public readonly array $resources,
        public readonly ?string $userId = null,
        public readonly ?string $clientId = null,
    ) {}

    public function auditRecord(): AuditRecord
    {
        return new AuditRecord(
            type: $this->type,
            userId: $this->userId,
            clientId: $this->clientId,
            context: [
                'scopes' => $this->scopes,
                'resources' => $this->resources,
            ],
            failure: true,
        );
    }
}
