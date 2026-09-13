<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Realms\Settings;

final readonly class ResourceSettings
{
    /**
     * @param  array<string, list<string>>  $resources  resource servers the realm serves besides itself, keyed by identifier
     *                                                  with the scopes they advertise: a path relative to the issuer (`mcp`)
     *                                                  is identified as `<issuer>/mcp` and published through RFC 9728
     *                                                  metadata, an absolute URI names an external resource server
     */
    public function __construct(
        public array $resources = [],
    ) {}

    public static function fromConfig(): self
    {
        $resources = [];

        foreach ((array) config('oidc.resources', []) as $identifier => $settings) {
            $scopes = is_array($settings) ? ($settings['scopes'] ?? []) : [];
            $resources[(string) $identifier] = array_values(array_filter((array) $scopes, is_string(...)));
        }

        return new self($resources);
    }
}
