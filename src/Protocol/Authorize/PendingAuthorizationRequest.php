<?php

declare(strict_types=1);

namespace Lock\Server\Protocol\Authorize;

use Illuminate\Http\Request;
use Lock\Server\Shared\Authentication\PendingAuthorization;
use Lock\Server\Shared\Protocol\AuthorizeRequest;

final readonly class PendingAuthorizationRequest implements PendingAuthorization
{
    public function __construct(private AuthorizeRequestSession $session) {}

    public function acrValues(Request $request): array
    {
        return $this->session->acrValues($request);
    }

    public function clientId(Request $request): ?string
    {
        return $this->session->peek($request)?->clientId;
    }

    public function scopes(Request $request): array
    {
        $authorizeRequest = $this->session->peek($request);

        return $authorizeRequest instanceof AuthorizeRequest ? $authorizeRequest->scopes : [];
    }
}
