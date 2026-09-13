<?php

declare(strict_types=1);

namespace Lock\Server\Clients;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Str;
use Lock\Server\Clients\Models\Client as ClientModel;
use Lock\Server\Shared\Clients\Client;
use Lock\Server\Shared\Clients\ClientAuthenticationException;
use Lock\Server\Shared\Clients\Clients;
use Lock\Server\Shared\Clients\TokenEndpointAuthMethod;
use Lock\Server\Shared\Realms\RealmResolver;
use RuntimeException;

/**
 * `client_id` is the wire identifier; foreign keys reference the primary key.
 */
class ClientRepository implements Clients
{
    public function __construct(private readonly RealmResolver $realms) {}

    public function find(string $clientId): ?Client
    {
        return ClientModel::query()->inRealm()->where('client_id', $clientId)->first()?->snapshot();
    }

    public function findByKey(string $key, ?string $realm = null): ?Client
    {
        return ClientModel::query()->inRealm($realm)->find($key)?->snapshot();
    }

    public function delete(string $key, string $realm): void
    {
        ClientModel::query()->inRealm($realm)->find($key)?->delete();
    }

    public function findActive(string $clientId): ?Client
    {
        $client = $this->find($clientId);

        return $client instanceof Client && ! $client->revoked ? $client : null;
    }

    public function firstParty(): Client
    {
        $clientId = $this->realms->current()->clients()->firstPartyClientId;

        return ($clientId === null ? null : $this->findActive($clientId))
            ?? throw new RuntimeException('The oidc.clients.first_party.client_id is not configured or does not exist.');
    }

    public function authenticate(string $clientId, ?string $secret, TokenEndpointAuthMethod $method): Client
    {
        $client = ClientModel::query()->inRealm()->where('client_id', $clientId)->whereNull('revoked_at')->first()
            ?? throw new ClientAuthenticationException('unknown_client');

        if ($client->token_endpoint_auth_method !== $method) {
            throw new ClientAuthenticationException('auth_method_mismatch');
        }

        if ($method->requiresSecret()) {
            $registered = $client->secret;

            if ($secret === null || $secret === '' || $registered === null || $registered === '' || ! hash_equals($registered, $secret)) {
                throw new ClientAuthenticationException('invalid_secret');
            }
        }

        return $client->snapshot();
    }

    public function logoutClientKeys(array $keys, string $realm): array
    {
        return ClientModel::query()->inRealm($realm)->whereIn('id', $keys)
            ->whereNotNull('backchannel_logout_uri')->pluck('id')->all();
    }

    /** @param  array<int, string>  $redirectUris */
    public function createAuthorizationCodeGrantClient(
        string $name,
        array $redirectUris,
        bool $confidential = true,
        ?Authenticatable $user = null,
    ): ClientModel {
        return $this->create(
            name: $name,
            grantTypes: ['authorization_code', 'refresh_token'],
            redirectUris: $redirectUris,
            confidential: $confidential,
            user: $user,
        );
    }

    public function createClientCredentialsGrantClient(string $name): ClientModel
    {
        return $this->create($name, ['client_credentials']);
    }

    public function regenerateSecret(ClientModel $client): bool
    {
        $client->secret = Str::random(40);

        return $client->save();
    }

    /**
     * @param  array<int, string>  $grantTypes
     * @param  array<int, string>  $redirectUris
     * @param  list<string>|null  $defaultScopes  overrides the realm's default scopes
     * @param  list<string>|null  $optionalScopes  overrides the realm's optional scopes
     */
    protected function create(
        string $name,
        array $grantTypes,
        array $redirectUris = [],
        bool $confidential = true,
        ?Authenticatable $user = null,
        ?string $clientId = null,
        ?array $defaultScopes = null,
        ?array $optionalScopes = null,
    ): ClientModel {
        $settings = $this->realms->current()->clients();
        $client = new ClientModel;
        $client->setAttribute($client->getKeyName(), $client->newUniqueId());

        $client->forceFill([
            'realm' => ClientModel::currentRealm(),
            // A generated client answers to its own key until someone gives it a
            // readable name; the two stay separate so renaming never touches tokens.
            'client_id' => $clientId ?? $client->getKey(),
            'name' => $name,
            'redirect_uris' => $redirectUris,
            'post_logout_redirect_uris' => [],
            'grant_types' => $grantTypes,
            'default_scopes' => $defaultScopes ?? $settings->defaultScopes,
            'optional_scopes' => $optionalScopes ?? $settings->optionalScopes,
            'token_endpoint_auth_method' => $confidential ? TokenEndpointAuthMethod::ClientSecretPost : TokenEndpointAuthMethod::None,
            'allowed_exchange_audiences' => [],
            'owner_type' => $user instanceof Authenticatable ? $user::class : null,
            'owner_id' => $user?->getAuthIdentifier(),
        ]);

        $client->secret = $confidential ? Str::random(40) : null;
        $client->save();

        return $client;
    }
}
