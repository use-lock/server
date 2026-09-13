<?php

declare(strict_types=1);

namespace Lock\Server\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Str;
use Lock\Server\Authentication\Models\PasswordResetToken;
use Lock\Server\Database\Factories\Concerns\ForUser;

/**
 * @extends Factory<PasswordResetToken>
 */
class PasswordResetTokenFactory extends Factory
{
    use ForUser;

    protected $model = PasswordResetToken::class;

    /** The column holds the hash `PasswordResetTokens` compares against, not the link's token. */
    public function definition(): array
    {
        return [
            'realm' => PasswordResetToken::currentRealm(),
            'user_id' => self::newUserId(...),
            'token' => hash('sha256', Str::random(64)),
            'created_at' => now(),
        ];
    }
}
