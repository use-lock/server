<?php
declare(strict_types=1);

namespace Lock\Server\Credentials\Ui\Support;

final class FactorMethodName
{
    /**
     * Keep host-registered providers readable without package translations.
     */
    public static function for(string $providerKey): string
    {
        $labelKey = "oidc-ui::auth.two-factor.method.{$providerKey}";

        return trans()->has($labelKey) ? __($labelKey) : $providerKey;
    }
}
