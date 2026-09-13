<?php

declare(strict_types=1);

namespace Lock\Server\Audit\Contracts;

use Lock\Server\Shared\Audit\AuditRecord;

interface AuditSink
{
    public function record(AuditRecord $record): void;
}
