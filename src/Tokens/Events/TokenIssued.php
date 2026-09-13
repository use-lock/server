<?php

declare(strict_types=1);

namespace Lock\Server\Tokens\Events;

use Illuminate\Contracts\Events\ShouldDispatchAfterCommit;
use Lock\Server\Shared\Audit\AuditEvent;
use Lock\Server\Shared\Audit\AuditEventType;
use Lock\Server\Shared\Audit\AuditRecord;

final class TokenIssued implements AuditEvent, ShouldDispatchAfterCommit
{
    public AuditEventType $type { get => AuditEventType::TokenIssued; }

    /**
     * @param  list<string>  $scopes
     * @param  list<string>  $audiences
     */
    public function __construct(
        public readonly string $realm,
        public readonly string $grantType,
        public readonly string $jti,
        public readonly array $scopes,
        public readonly ?string $clientId = null,
        public readonly ?string $userId = null,
        public readonly ?string $sid = null,
        public readonly array $audiences = [],
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
                'jti' => $this->jti,
                'scopes' => $this->scopes,
                'audiences' => $this->audiences === [] ? null : $this->audiences,
            ],
            realm: $this->realm,
        );
    }
}
