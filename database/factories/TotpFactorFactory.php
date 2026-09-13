<?php

declare(strict_types=1);

namespace Lock\Server\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Str;
use Lock\Server\Credentials\Models\TotpFactor;
use Lock\Server\Database\Factories\Concerns\ForUser;

/**
 * @extends Factory<TotpFactor>
 */
class TotpFactorFactory extends Factory
{
    use ForUser;

    protected $model = TotpFactor::class;

    public function definition(): array
    {
        return [
            'user_id' => self::newUserId(...),
            'name' => 'Authenticator app',
            'secret' => Str::random(32),
        ];
    }

    public function confirmed(): static
    {
        return $this->state(['confirmed_at' => now()]);
    }
}
