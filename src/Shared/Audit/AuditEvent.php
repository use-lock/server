<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Audit;

/**
 * Dispatch to record through the configured audit sink. Hosts may supply
 * their own backed enum for event types.
 */
interface AuditEvent
{
    public \BackedEnum $type { get; }

    public function auditRecord(): AuditRecord;
}
