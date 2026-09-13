<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Authentication;

use Illuminate\Http\Request;

/**
 * Exposes pending client and scopes without coupling login to protocol storage.
 */
interface PendingAuthorization
{
    /** @return list<string> */
    public function acrValues(Request $request): array;

    public function clientId(Request $request): ?string;

    /** @return list<string> */
    public function scopes(Request $request): array;
}
