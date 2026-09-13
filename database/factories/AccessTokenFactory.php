<?php

declare(strict_types=1);

namespace Lock\Server\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use Lock\Server\Clients\Models\Client;
use Lock\Server\Database\Factories\Concerns\ForClient;
use Lock\Server\Database\Factories\Concerns\ForUser;
use Lock\Server\Tokens\Models\AccessToken;

/**
 * @extends Factory<AccessToken>
 */
class AccessTokenFactory extends Factory
{
    use ForClient, ForUser;

    protected $model = AccessToken::class;

    public function definition(): array
    {
        return [
            'id' => bin2hex(random_bytes(40)),
            'realm' => AccessToken::currentRealm(),
            'user_id' => self::newUserId(...),
            'client_id' => fn (): string => (string) Client::factory()->create()->getKey(),
            'scopes' => ['openid'],
            'expires_at' => now()->addHour(),
        ];
    }

    public function revoked(): static
    {
        return $this->state(['revoked_at' => now()]);
    }

    public function expired(): static
    {
        return $this->state(['expires_at' => now()->subMinute()]);
    }
}
