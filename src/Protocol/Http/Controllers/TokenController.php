<?php

declare(strict_types=1);

namespace Lock\Server\Protocol\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Lock\Server\Protocol\TokenEndpoint;
use Lock\Server\Protocol\TokenResponse;

class TokenController
{
    public function __construct(protected TokenEndpoint $endpoint) {}

    public function __invoke(Request $request): JsonResponse
    {
        return new TokenResponse($this->endpoint->issue($request))->toResponse($request);
    }
}
