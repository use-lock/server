<?php

declare(strict_types=1);

namespace Lock\Server\Brokering;

use Closure;
use Lock\Server\Brokering\Providers\AppleProvider;
use Lock\Server\Brokering\Providers\GenericOidcProvider;
use Lock\Server\Brokering\Providers\GitHubProvider;
use Lock\Server\Brokering\Providers\GoogleProvider;
use Lock\Server\Shared\Brokering\SocialProvider;
use Lock\Server\Shared\Brokering\SocialProviderRegistry as SocialProviderRegistryContract;
use Lock\Server\Shared\Realms\RealmResolver;

/**
 * Resolves social providers from `oidc.social.providers` config. A provider is
 * active only when its client_id is configured; `extend()` registers custom
 * driver factories keyed by driver name.
 */
class SocialProviderRegistry implements SocialProviderRegistryContract
{
    public function __construct(private readonly RealmResolver $realms) {}

    /**
     * @var array<string, class-string<SocialProvider>>
     */
    private const array DRIVERS = [
        'oidc' => GenericOidcProvider::class,
        'google' => GoogleProvider::class,
        'apple' => AppleProvider::class,
        'github' => GitHubProvider::class,
    ];

    /**
     * @var array<string, Closure(string, array<string, mixed>): SocialProvider>
     */
    private array $customCreators = [];

    /**
     * @param  Closure(string, array<string, mixed>): SocialProvider  $creator
     */
    public function extend(string $driver, Closure $creator): void
    {
        $this->customCreators[$driver] = $creator;
    }

    public function get(string $key): ?SocialProvider
    {
        $config = $this->realms->current()->brokering()->provider($key);

        if ($config === null || ! is_string($config['client_id'] ?? null) || $config['client_id'] === '') {
            return null;
        }

        $driver = is_string($config['driver'] ?? null) ? $config['driver'] : $key;

        if (isset($this->customCreators[$driver])) {
            return ($this->customCreators[$driver])($key, $config);
        }

        $class = self::DRIVERS[$driver] ?? null;

        return $class === null ? null : new $class($key, $config);
    }

    /**
     * @return array<string, SocialProvider>
     */
    public function enabled(): array
    {
        $providers = [];

        foreach (array_keys($this->realms->current()->brokering()->providers) as $key) {
            $provider = $this->get((string) $key);

            if ($provider instanceof SocialProvider) {
                $providers[(string) $key] = $provider;
            }
        }

        return $providers;
    }
}
