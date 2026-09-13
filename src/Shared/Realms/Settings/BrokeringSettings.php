<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Realms\Settings;

final readonly class BrokeringSettings
{
    /**
     * @param  array<string, array<string, mixed>>  $providers  upstream identity providers keyed by provider key
     * @param  bool  $linkByVerifiedEmail  attach an upstream identity to a local user with a matching verified email
     * @param  bool  $autoProvision  create a local user on first upstream login
     */
    public function __construct(
        public array $providers = [],
        public bool $linkByVerifiedEmail = true,
        public bool $autoProvision = true,
    ) {}

    public static function fromConfig(): self
    {
        /** @var array<string, array<string, mixed>> $providers */
        $providers = array_filter((array) config('oidc.social.providers', []), is_array(...));

        return new self(
            providers: $providers,
            linkByVerifiedEmail: (bool) config('oidc.social.link_by_verified_email', true),
            autoProvision: (bool) config('oidc.social.auto_provision', true),
        );
    }

    /**
     * @return array<string, mixed>|null
     */
    public function provider(string $key): ?array
    {
        return $this->providers[$key] ?? null;
    }
}
