<?php

declare(strict_types=1);

namespace Lock\Server\SigningKeys;

use RuntimeException;

final class SigningKeyPair
{
    public function __construct(public readonly string $publicKeyPem, public readonly ?string $privateKeyPem = null, private ?string $kid = null) {}

    /**
     * Derived from the public key (RFC 7638) unless the store carries one, so a
     * store that persists its own kid keeps it stable across PEM re-encodings.
     */
    public function kid(): string
    {
        return $this->kid ??= Jwk::fromPem($this->publicKeyPem)['kid'];
    }

    public function privateKey(): string
    {
        return $this->privateKeyPem ?? throw new RuntimeException(
            "The OIDC signing key [{$this->kid()}] carries no private key and cannot sign.",
        );
    }
}
