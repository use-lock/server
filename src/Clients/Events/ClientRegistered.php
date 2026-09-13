<?php

declare(strict_types=1);

namespace Lock\Server\Clients\Events;

use Illuminate\Contracts\Events\ShouldDispatchAfterCommit;
use Lock\Server\Shared\Audit\AuditEvent;
use Lock\Server\Shared\Audit\AuditEventType;
use Lock\Server\Shared\Audit\AuditRecord;

final class ClientRegistered implements AuditEvent, ShouldDispatchAfterCommit
{
    public AuditEventType $type { get => AuditEventType::ClientRegistered; }

    /**
     * @param  list<string>  $redirectUris
     */
    public function __construct(
        public readonly string $clientId,
        public readonly string $name,
        public readonly array $redirectUris,
        public readonly string $tokenEndpointAuthMethod,
        public readonly string $realm,
    ) {}

    public function auditRecord(): AuditRecord
    {
        return new AuditRecord(
            type: $this->type,
            clientId: $this->clientId,
            context: [
                'client_name' => $this->name,
                'redirect_uris' => $this->redirectUris,
                'token_endpoint_auth_method' => $this->tokenEndpointAuthMethod,
            ],
            realm: $this->realm,
        );
    }
}
