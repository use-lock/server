<?php

declare(strict_types=1);

namespace Lock\Server\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use Lock\Server\Database\Factories\Concerns\ForUser;
use Lock\Server\Sessions\Models\OidcSession;

/**
 * @extends Factory<OidcSession>
 */
class OidcSessionFactory extends Factory
{
    use ForUser;

    protected $model = OidcSession::class;

    public function definition(): array
    {
        return [
            'realm' => OidcSession::currentRealm(),
            'user_id' => self::newUserId(...),
            'created_at' => now(),
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
