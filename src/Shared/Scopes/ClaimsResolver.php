<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Scopes;

interface ClaimsResolver
{
    /**
     * The claims to emit, already narrowed to the request's scopes and audience.
     * Protocol claims the caller owns (sub, iss, aud, ...) are ignored.
     *
     * @return array<string, mixed>
     */
    public function resolve(ClaimsRequest $request): array;
}
