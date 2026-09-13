<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Credentials;

final readonly class FactorVerification
{
    /**
     * @param  list<string>  $amr
     */
    public function __construct(
        public bool $verified,
        public array $amr = [],
    ) {}
}
