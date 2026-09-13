<?php

declare(strict_types=1);

namespace Lock\Server\Audit\Sinks;

use Lock\Server\Audit\Contracts\AuditSink;
use Lock\Server\Shared\Audit\AuditRecord;

final class NullAuditSink implements AuditSink
{
    public function record(AuditRecord $record): void {}
}
