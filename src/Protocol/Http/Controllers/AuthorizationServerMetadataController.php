<?php

declare(strict_types=1);

namespace Lock\Server\Protocol\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Lock\Server\Protocol\ProviderMetadata;

/**
 * RFC 8414 §3.1: insert the well-known segment before the issuer path.
 */
class AuthorizationServerMetadataController
{
    /**
     * Discover the realm's OAuth authorization server metadata.
     *
     * This public GET returns the same 200 JSON metadata document as OpenID
     * Connect discovery, including its OIDC extensions. Endpoint URLs and
     * capabilities reflect the current realm. Responses are publicly cacheable
     * for 3600 seconds. RFC 8414 places the well-known segment before any issuer
     * path, unlike the OpenID Connect discovery URL.
     *
     * @see ProviderMetadata
     */
    public function __invoke(ProviderMetadata $metadata): JsonResponse
    {
        return response()->json($metadata->document())->header('Cache-Control', 'max-age=3600, public');
    }
}
