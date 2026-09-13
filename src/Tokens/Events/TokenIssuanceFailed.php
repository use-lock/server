<?php

declare(strict_types=1);

namespace Lock\Server\Tokens\Events;

use Lock\Server\Shared\Audit\AuditEvent;
use Lock\Server\Shared\Audit\AuditEventType;
use Lock\Server\Shared\Audit\AuditRecord;

final class TokenIssuanceFailed implements AuditEvent
{
    public AuditEventType $type { get => AuditEventType::TokenIssuanceFailed; }

    public function __construct(
        public readonly string $grantType,
        public readonly string $reason,
        public readonly ?string $clientId = null,
        public readonly ?string $userId = null,
        public readonly ?string $sid = null,
        public readonly ?string $denyReason = null,
        public readonly ?string $scope = null,
    ) {}

    public function auditRecord(): AuditRecord
    {
        return new AuditRecord(
            type: $this->type,
            userId: $this->userId,
            clientId: $this->clientId,
            sid: $this->sid,
            context: [
                'grant_type' => $this->grantType,
                'reason' => $this->reason,
                'deny_reason' => $this->denyReason,
                'scope' => $this->scope,
            ],
            failure: true,
        );
    }
}
