<?php

declare(strict_types=1);

namespace Lock\Server\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use Lock\Server\Clients\Models\Client;
use Lock\Server\Consents\Models\Consent;
use Lock\Server\Database\Factories\Concerns\ForClient;
use Lock\Server\Database\Factories\Concerns\ForUser;
use Lock\Server\Shared\Realms\IssuerResolver;

/**
 * @extends Factory<Consent>
 */
class ConsentFactory extends Factory
{
    use ForClient, ForUser;

    protected $model = Consent::class;

    public function definition(): array
    {
        return [
            'realm' => Consent::currentRealm(),
            'user_id' => self::newUserId(...),
            'client_id' => fn (): string => (string) Client::factory()->create()->getKey(),
            'resource' => fn (): string => app(IssuerResolver::class)->url(),
            'scopes' => ['openid'],
            'granted_at' => now(),
        ];
    }

    public function revoked(): static
    {
        return $this->state(['revoked_at' => now()]);
    }
}
