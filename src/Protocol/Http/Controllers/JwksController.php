<?php

declare(strict_types=1);

namespace Lock\Server\Protocol\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Lock\Server\Shared\SigningKeys\Keyring;

class JwksController
{
    public function __construct(private readonly Keyring $keyring) {}

    public function __invoke(): JsonResponse
    {
        return response()
            ->json(['keys' => $this->keyring->publicKeys()])
            ->header('Cache-Control', 'max-age=3600, public');
    }
}
