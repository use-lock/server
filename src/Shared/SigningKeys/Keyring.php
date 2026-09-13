<?php

declare(strict_types=1);

namespace Lock\Server\Shared\SigningKeys;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Token\Plain;

interface Keyring
{
    public function builder(): Builder;

    public function sign(Builder $builder): string;

    public function verifies(Plain $token): bool;

    /** @return list<array{kty: string, use: string, alg: string, kid: string, n: string, e: string}> */
    public function publicKeys(): array;
}
