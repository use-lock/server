<?php

declare(strict_types=1);

namespace Lock\Server\Protocol\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Lock\Server\Shared\SigningKeys\Keyring;

class JwksController
{
    public function __construct(private readonly Keyring $keyring) {}

    /**
     * Read the realm's public signing keys.
     *
     * This public GET returns 200 JSON with a `keys` array in JSON Web Key Set
     * format. Consumers use these keys to verify signatures on issued tokens;
     * private key material is never returned. Responses are publicly cacheable
     * for 3600 seconds.
     */
    public function __invoke(): JsonResponse
    {
        return response()
            ->json(['keys' => $this->keyring->publicKeys()])
            ->header('Cache-Control', 'max-age=3600, public');
    }
}
