<?php

declare(strict_types=1);

namespace Lock\Server\SigningKeys;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Builder as TokenBuilder;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Validator;
use Lock\Server\Shared\SigningKeys\Keyring;

final readonly class StoredKeyring implements Keyring
{
    public function __construct(private SigningKeyStore $store) {}

    public function builder(): Builder
    {
        return TokenBuilder::new(new JoseEncoder, ChainedFormatter::default());
    }

    public function sign(Builder $builder): string
    {
        $key = $this->store->signingKey();

        return $builder->withHeader('kid', $key->kid())
            ->getToken(new Sha256, InMemory::plainText($key->privateKey()))
            ->toString();
    }

    public function verifies(Plain $token): bool
    {
        $validator = new Validator;

        return array_any($this->store->verificationKeys(), fn (SigningKeyPair $key): bool => $validator->validate($token, new SignedWith(new Sha256, InMemory::plainText($key->publicKeyPem))));
    }

    /** @return list<array{kty: string, use: string, alg: string, kid: string, n: string, e: string}> */
    public function publicKeys(): array
    {
        $keys = [];

        foreach ($this->store->verificationKeys() as $key) {
            $jwk = Jwk::fromPem($key->publicKeyPem);
            $jwk['kid'] = $key->kid();
            $keys[$jwk['kid']] = $jwk;
        }

        return array_values($keys);
    }
}
