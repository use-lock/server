<?php
declare(strict_types=1);

namespace Lock\Server\Credentials\Ui\Support;

use Lock\Server\Shared\Credentials\EnrollmentOption;
use Lock\Server\Shared\Credentials\FactorRole;
use Lock\Server\Shared\Credentials\FactorSetupKind;

/**
 * Host providers may supply oidc-ui::security.option.{id}.* translations; unknown options retain a fallback.
 */
final class EnrollmentOptionLabels
{
    public static function label(EnrollmentOption $option): string
    {
        return self::translate($option, 'label') ?? $option->id;
    }

    public static function description(EnrollmentOption $option): string
    {
        return self::translate($option, 'description') ?? '';
    }

    public static function role(EnrollmentOption $option): string
    {
        return $option->role === FactorRole::LoginAndSecondFactor
            ? __('oidc-ui::security.role.login-and-second-factor')
            : __('oidc-ui::security.role.second-factor-only');
    }

    /**
     * Use sprite names because Lattice’s curated Icon enum lacks these provider icons.
     */
    public static function icon(EnrollmentOption $option): string
    {
        return match ($option->id) {
            'passkey' => 'fingerprint',
            'security_key' => 'usb',
            'totp' => 'smartphone',
            default => $option->setupKind === FactorSetupKind::Ceremony ? 'key-round' : 'shield-check',
        };
    }

    private static function translate(EnrollmentOption $option, string $suffix): ?string
    {
        $key = "oidc-ui::security.option.{$option->id}.{$suffix}";

        return trans()->has($key) ? __($key) : null;
    }
}
