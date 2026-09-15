<?php

declare(strict_types=1);

namespace Lock\Server\Protocol\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Lock\Server\Protocol\ProviderMetadata;

class DiscoveryController
{
    /**
     * Discover the realm's OpenID Connect provider configuration.
     *
     * This public GET returns 200 JSON with the issuer, endpoint URLs, signing
     * algorithms, supported grants, scopes, claims and client authentication
     * methods. Values reflect the current realm and available routes; dynamic
     * registration is advertised only when enabled. Responses are publicly
     * cacheable for 3600 seconds.
     *
     * @see ProviderMetadata
     */
    public function __invoke(ProviderMetadata $metadata): JsonResponse
    {
        return response()->json($metadata->document())->header('Cache-Control', 'max-age=3600, public');
    }
}
