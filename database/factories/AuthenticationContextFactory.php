<?php

declare(strict_types=1);

namespace Lock\Server\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use Lock\Server\Database\Factories\Concerns\ForUser;
use Lock\Server\Tokens\Models\AuthenticationContext;

/**
 * @extends Factory<AuthenticationContext>
 */
class AuthenticationContextFactory extends Factory
{
    use ForUser;

    protected $model = AuthenticationContext::class;

    public function definition(): array
    {
        return [
            'realm' => AuthenticationContext::currentRealm(),
            'user_id' => self::newUserId(...),
            'amr' => ['pwd'],
            'auth_time' => now()->getTimestamp(),
            'id_token_claims' => [],
            'access_token_claims' => [],
            'created_at' => now(),
            'expires_at' => now()->addDays(30),
        ];
    }
}
