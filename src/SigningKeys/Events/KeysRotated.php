<?php

declare(strict_types=1);

namespace Lock\Server\SigningKeys\Events;

use Illuminate\Contracts\Events\ShouldDispatchAfterCommit;
use Lock\Server\Shared\Audit\AuditEvent;
use Lock\Server\Shared\Audit\AuditEventType;
use Lock\Server\Shared\Audit\AuditRecord;

final class KeysRotated implements AuditEvent, ShouldDispatchAfterCommit
{
    public AuditEventType $type { get => AuditEventType::KeysRotated; }

    public function __construct(public readonly string $kid, public readonly string $realm) {}

    public function auditRecord(): AuditRecord
    {
        return new AuditRecord(
            type: $this->type,
            context: [
                'kid' => $this->kid,
            ],
            realm: $this->realm,
        );
    }
}
