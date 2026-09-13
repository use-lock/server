<?php

declare(strict_types=1);

namespace Lock\Server\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Str;
use Lock\Server\Brokering\Models\SocialAccount;
use Lock\Server\Database\Factories\Concerns\ForUser;

/**
 * @extends Factory<SocialAccount>
 */
class SocialAccountFactory extends Factory
{
    use ForUser;

    protected $model = SocialAccount::class;

    public function definition(): array
    {
        return [
            'realm' => SocialAccount::currentRealm(),
            'user_id' => self::newUserId(...),
            'provider' => 'github',
            'provider_user_id' => (string) Str::uuid(),
            'email' => Str::uuid()->toString().'@example.com',
        ];
    }
}
