<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Realms\Settings;

final readonly class KeySettings
{
    /**
     * @param  int  $keySize  RSA modulus length in bits for generated signing keys
     */
    public function __construct(public int $keySize = 2048) {}

    public static function fromConfig(): self
    {
        return new self(keySize: (int) config('oidc.keys.size', 2048));
    }
}
