<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Audit;

use DateTimeImmutable;

final readonly class AuditRecord
{
    /** @var array<string, mixed> */
    public array $context;

    /**
     * @param  array<string, mixed>  $context
     */
    public function __construct(
        public \BackedEnum $type,
        public ?string $userId = null,
        public ?string $clientId = null,
        public ?string $sid = null,
        array $context = [],
        public bool $failure = false,
        public ?string $ip = null,
        public ?string $userAgent = null,
        public DateTimeImmutable $occurredAt = new DateTimeImmutable,
        public ?string $realm = null,
    ) {
        $this->context = array_filter($context, static fn (mixed $value): bool => $value !== null);
    }

    public function category(): string
    {
        return explode('.', (string) $this->type->value)[0];
    }

    public function withRequestContext(?string $ip, ?string $userAgent, ?string $sid): self
    {
        return new self(
            type: $this->type,
            userId: $this->userId,
            clientId: $this->clientId,
            sid: $this->sid ?? $sid,
            context: $this->context,
            failure: $this->failure,
            ip: $ip,
            userAgent: $userAgent,
            occurredAt: $this->occurredAt,
            realm: $this->realm,
        );
    }
}
