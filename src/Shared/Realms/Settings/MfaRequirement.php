<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Realms\Settings;

/**
 * IfEnrolled challenges existing factors; Always also requires enrollment
 * before login can complete.
 */
enum MfaRequirement: string
{
    case Never = 'never';
    case IfEnrolled = 'if_enrolled';
    case Always = 'always';

    public static function fromConfig(mixed $value): self
    {
        return is_string($value) ? self::tryFrom($value) ?? self::IfEnrolled : self::IfEnrolled;
    }
}
