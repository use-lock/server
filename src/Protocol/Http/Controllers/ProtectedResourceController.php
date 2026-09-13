<?php

declare(strict_types=1);

namespace Lock\Server\Protocol\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Lock\Server\Shared\Realms\IssuerResolver;
use Lock\Server\Shared\Realms\RealmAudiences;

/**
 * RFC 9728 protected resource metadata for the path-relative resources in
 * `oidc.resources`. The resource identifier is the audience the realm's
 * bearer guard accepts for it; {@see RealmAudiences} derives it from the
 * issuer, never the request host.
 */
class ProtectedResourceController
{
    public function __invoke(IssuerResolver $issuer, RealmAudiences $audiences, string $path = ''): JsonResponse
    {
        $scopes = $audiences->advertisedScopes($path);

        abort_if($scopes === null, 404);

        return response()->json([
            'resource' => $audiences->protectedResource($path),
            'authorization_servers' => [$issuer->url()],
            'scopes_supported' => $scopes,
            'bearer_methods_supported' => ['header'],
        ])->header('Cache-Control', 'max-age=3600, public');
    }
}
