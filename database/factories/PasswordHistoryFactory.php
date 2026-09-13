<?php

declare(strict_types=1);

namespace Lock\Server\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Lock\Server\Credentials\Models\PasswordHistory;
use Lock\Server\Database\Factories\Concerns\ForUser;

/**
 * @extends Factory<PasswordHistory>
 */
class PasswordHistoryFactory extends Factory
{
    use ForUser;

    protected $model = PasswordHistory::class;

    public function definition(): array
    {
        return [
            'user_id' => self::newUserId(...),
            'hash' => Hash::make(Str::random(16)),
            'created_at' => now(),
        ];
    }
}
