<?php

declare(strict_types=1);

namespace Lock\Server\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Str;
use Lock\Server\Clients\Models\Client;
use Lock\Server\Shared\Clients\TokenEndpointAuthMethod;
use Lock\Server\Tokens\Grants\AuthorizationCodeGrant;
use Lock\Server\Tokens\Grants\RefreshTokenGrant;

/**
 * @extends Factory<Client>
 */
class ClientFactory extends Factory
{
    protected $model = Client::class;

    public function definition(): array
    {
        return [
            'realm' => Client::currentRealm(),
            'client_id' => (string) Str::uuid(),
            'name' => 'Test Client',
            'secret' => Str::random(40),
            'token_endpoint_auth_method' => TokenEndpointAuthMethod::ClientSecretPost,
            'redirect_uris' => ['https://rp.test/callback'],
            'post_logout_redirect_uris' => [],
            'grant_types' => [AuthorizationCodeGrant::TYPE, RefreshTokenGrant::TYPE],
            'default_scopes' => ['openid'],
            'optional_scopes' => [],
            'allowed_exchange_audiences' => [],
        ];
    }

    public function public(): static
    {
        return $this->state([
            'secret' => null,
            'token_endpoint_auth_method' => TokenEndpointAuthMethod::None,
        ]);
    }

    public function revoked(): static
    {
        return $this->state(['revoked_at' => now()]);
    }
}
