<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Credentials;

/**
 * Code returns proof of a server-issued secret; Ceremony supplies browser-generated proof.
 */
enum FactorSetupKind: string
{
    case Code = 'code';

    case Ceremony = 'ceremony';
}
