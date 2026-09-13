<?php

declare(strict_types=1);

namespace Lock\Server\Protocol\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Lock\Server\Protocol\ProviderMetadata;

class DiscoveryController
{
    public function __invoke(ProviderMetadata $metadata): JsonResponse
    {
        return response()->json($metadata->document())->header('Cache-Control', 'max-age=3600, public');
    }
}
