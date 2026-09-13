<?php

declare(strict_types=1);

namespace Lock\Server\Database\Factories\Concerns;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Database\Eloquent\Model;
use RuntimeException;

trait ForUser
{
    public function forUser(Authenticatable $user): static
    {
        return $this->state(['user_id' => (string) $user->getAuthIdentifier()]);
    }

    /**
     * `user_id` may be constrained, so the default has to name a user that
     * exists. Which model that is belongs to the application, so it comes from
     * the guard's provider and its own factory makes one.
     */
    protected static function newUserId(): string
    {
        $provider = (string) config('oidc.auth.provider', 'users');
        $model = config("auth.providers.{$provider}.model");

        if (! is_string($model) || ! is_a($model, Model::class, true)) {
            throw new RuntimeException("The [{$provider}] user provider does not name an Eloquent model.");
        }

        return (string) Factory::factoryForModel($model)->createOne()->getKey();
    }
}
