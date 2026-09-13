<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Realms\Settings;

/**
 * Registration and password reset require the Password login method.
 */
enum LoginMethod: string
{
    case Password = 'password';
    case Passkey = 'passkey';
    case Social = 'social';

    /**
     * @param  array<int, mixed>  $values
     * @return list<self>
     */
    public static function listFromConfig(array $values): array
    {
        return array_values(array_filter(array_map(
            fn (mixed $value): ?self => is_string($value) ? self::tryFrom($value) : null,
            $values,
        )));
    }
}
