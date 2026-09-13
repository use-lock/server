<?php

declare(strict_types=1);

namespace Lock\Server\Support\Testing;

use Closure;
use Lock\Server\Audit\Contracts\AuditSink;
use Lock\Server\Shared\Audit\AuditRecord;
use PHPUnit\Framework\Assert;

final class FakeAuditSink implements AuditSink
{
    /** @var list<AuditRecord> */
    private array $records = [];

    public function record(AuditRecord $record): void
    {
        $this->records[] = $record;
    }

    /**
     * @return list<AuditRecord>
     */
    public function records(?\BackedEnum $type = null): array
    {
        return array_values(array_filter(
            $this->records,
            static fn (AuditRecord $record): bool => ! $type instanceof \BackedEnum || $record->type === $type,
        ));
    }

    /**
     * @param  (Closure(AuditRecord): bool)|null  $filter
     */
    public function assertRecorded(\BackedEnum $type, ?Closure $filter = null): AuditRecord
    {
        $records = $this->records($type);

        Assert::assertNotEmpty($records, "Expected audit record [{$type->value}] was not recorded.");

        if (! $filter instanceof Closure) {
            return $records[0];
        }

        $matching = array_values(array_filter($records, $filter));

        Assert::assertNotEmpty($matching, "Audit record [{$type->value}] was recorded, but none matched the given filter.");

        return $matching[0];
    }

    public function assertNotRecorded(\BackedEnum $type): void
    {
        Assert::assertSame([], $this->records($type), "Unexpected audit record [{$type->value}] was recorded.");
    }

    public function assertNothingRecorded(): void
    {
        Assert::assertSame([], $this->records, 'Expected no audit records, but some were recorded.');
    }
}
