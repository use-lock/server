<?php

declare(strict_types=1);

namespace Lock\Server\SigningKeys;

use Lock\Server\Shared\Realms\RealmResolver;
use phpseclib3\Crypt\RSA;
use phpseclib3\Crypt\RSA\PrivateKey;
use Throwable;

final readonly class SigningKeyGenerator
{
    public function __construct(
        private SigningKeyStore $store,
        private RealmResolver $realms,
    ) {}

    public function generate(): GeneratedSigningKeys
    {
        /** @var PrivateKey $key */
        $key = RSA::createKey($this->realms->current()->keys()->keySize);

        $privatePem = (string) $key;
        $publicPem = (string) $key->getPublicKey();

        return new GeneratedSigningKeys(
            privateKeyPem: $privatePem,
            publicKeyPem: $publicPem,
            kid: Jwk::fromPem($publicPem)['kid'],
        );
    }

    public function hasKeys(): bool
    {
        try {
            $this->store->signingKey();

            return true;
        } catch (Throwable) {
            return false;
        }
    }
}
