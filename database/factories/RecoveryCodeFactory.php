<?php

declare(strict_types=1);

namespace Lock\Server\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Str;
use Lock\Server\Credentials\Models\RecoveryCode;
use Lock\Server\Database\Factories\Concerns\ForUser;

/**
 * @extends Factory<RecoveryCode>
 */
class RecoveryCodeFactory extends Factory
{
    use ForUser;

    protected $model = RecoveryCode::class;

    public function definition(): array
    {
        return [
            'user_id' => self::newUserId(...),
            'code' => Str::random(20),
        ];
    }

    public function used(): static
    {
        return $this->state(['used_at' => now()]);
    }
}
