<?php

declare(strict_types=1);

namespace Lock\Server\SigningKeys;

/**
 * Bound as a singleton and held by singletons such as AccessTokenMinter, so an
 * implementation must read any request-dependent state (a realm, a host) inside
 * its methods rather than capture it in the constructor.
 */
interface SigningKeyStore
{
    /** @throws \RuntimeException when the backend holds no usable signing key */
    public function signingKey(): SigningKeyPair;

    /**
     * Every key signatures may verify against, the signing key first. Verification
     * and JWKS must use the same set, or rotation invalidates live tokens that
     * relying parties still consider valid. Entries need no private key.
     *
     * @return non-empty-list<SigningKeyPair>
     */
    public function verificationKeys(): array;

    /**
     * Persist a new keypair, retaining the current one for verification.
     *
     * @throws \RuntimeException when the backend cannot persist the keys
     */
    public function rotate(GeneratedSigningKeys $keys): void;
}
