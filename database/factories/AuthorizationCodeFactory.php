<?php

declare(strict_types=1);

namespace Lock\Server\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Str;
use Lock\Server\Clients\Models\Client;
use Lock\Server\Database\Factories\Concerns\ForClient;
use Lock\Server\Database\Factories\Concerns\ForUser;
use Lock\Server\Tokens\Models\AuthorizationCode;

/**
 * @extends Factory<AuthorizationCode>
 */
class AuthorizationCodeFactory extends Factory
{
    use ForClient, ForUser;

    protected $model = AuthorizationCode::class;

    public function definition(): array
    {
        return [
            'code' => bin2hex(random_bytes(40)),
            'realm' => AuthorizationCode::currentRealm(),
            'user_id' => self::newUserId(...),
            'client_id' => fn (): string => (string) Client::factory()->create()->getKey(),
            'scopes' => ['openid'],
            'code_challenge' => Str::random(43),
            'code_challenge_method' => 'S256',
            'expires_at' => now()->addMinutes(10),
        ];
    }
}
