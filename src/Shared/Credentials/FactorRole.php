<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Credentials;

/**
 * WebAuthn supports login and MFA; TOTP supports MFA only.
 */
enum FactorRole: string
{
    case LoginAndSecondFactor = 'login_and_second_factor';

    case SecondFactorOnly = 'second_factor_only';
}
