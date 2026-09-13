<?php

declare(strict_types=1);

namespace Lock\Server\Credentials\Ui\Components;

use Illuminate\Support\Facades\Route;
use Lattice\Ui\Components\Component;

class PasskeyVerify extends Component
{
    public string $optionsUrl;

    public string $submitUrl;

    public ?string $label = null;

    public ?string $loadingLabel = null;

    public ?string $separator = null;

    public static function make(
        string $optionsUrl,
        string $submitUrl,
        ?string $label = null,
        ?string $loadingLabel = null,
        ?string $separator = null,
    ): static {
        $component = new static;
        $component->optionsUrl = $optionsUrl;
        $component->submitUrl = $submitUrl;
        $component->label = $label;
        $component->loadingLabel = $loadingLabel;
        $component->separator = $separator;

        return $component;
    }

    /**
     * Hide the component when the host has not registered ceremony routes.
     */
    public static function makeIfAvailable(
        string $optionsRoute,
        string $submitRoute,
        ?string $label = null,
        ?string $loadingLabel = null,
        ?string $separator = null,
    ): ?static {
        if (! Route::has($optionsRoute) || ! Route::has($submitRoute)) {
            return null;
        }

        return static::make(
            route($optionsRoute, absolute: false),
            route($submitRoute, absolute: false),
            $label,
            $loadingLabel,
            $separator,
        );
    }

    protected function type(): string
    {
        return 'oidc.passkey-verify';
    }
}
