<?php

declare(strict_types=1);

namespace Lock\Server\Clients;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;
use InvalidArgumentException;
use Lock\Server\Clients\Models\Client as ClientModel;
use Lock\Server\Shared\Clients\Client;
use Lock\Server\Shared\Clients\ClientAuthenticationException;
use Lock\Server\Shared\Clients\Clients;
use Lock\Server\Shared\Clients\TokenEndpointAuthMethod;
use Lock\Server\Shared\Realms\RealmResolver;
use RuntimeException;
use SensitiveParameter;

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

    /** @param  list<string>  $redirectUris */
    public function createAuthorizationCodeGrantClient(
        string $name,
        array $redirectUris,
        bool $confidential = true,
        ?Model $owner = null,
    ): ClientModel {
        return $this->create(
            name: $name,
            grantTypes: ['authorization_code', 'refresh_token'],
            redirectUris: $redirectUris,
            authMethod: $confidential ? TokenEndpointAuthMethod::ClientSecretPost : TokenEndpointAuthMethod::None,
            owner: $owner,
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
     * Creates a client in the current realm. A confidential client gets a
     * generated secret unless one is given, e.g. to provision a client whose
     * credentials already live in a relying party's environment.
     *
     * @param  list<string>  $grantTypes
     * @param  list<string>  $redirectUris
     * @param  list<string>|null  $defaultScopes  overrides the realm's default scopes
     * @param  list<string>|null  $optionalScopes  overrides the realm's optional scopes
     * @param  list<string>  $postLogoutRedirectUris
     * @param  list<string>  $allowedAudiences  the resources the client may request tokens for (RFC 8707)
     */
    public function create(
        string $name,
        array $grantTypes,
        array $redirectUris = [],
        TokenEndpointAuthMethod $authMethod = TokenEndpointAuthMethod::ClientSecretPost,
        ?Model $owner = null,
        ?string $clientId = null,
        #[SensitiveParameter] ?string $secret = null,
        ?array $defaultScopes = null,
        ?array $optionalScopes = null,
        array $postLogoutRedirectUris = [],
        array $allowedAudiences = [],
        ?string $backchannelLogoutUri = null,
        bool $backchannelLogoutSessionRequired = false,
        bool $consentRequired = true,
    ): ClientModel {
        if ($secret !== null && ! $authMethod->requiresSecret()) {
            throw new InvalidArgumentException('A public client cannot have a secret.');
        }

        if ($secret === '') {
            throw new InvalidArgumentException('A client secret cannot be empty.');
        }

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
            'post_logout_redirect_uris' => $postLogoutRedirectUris,
            'grant_types' => $grantTypes,
            'default_scopes' => $defaultScopes ?? $settings->defaultScopes,
            'optional_scopes' => $optionalScopes ?? $settings->optionalScopes,
            'token_endpoint_auth_method' => $authMethod,
            'allowed_exchange_audiences' => $allowedAudiences,
            'backchannel_logout_uri' => $backchannelLogoutUri,
            'backchannel_logout_session_required' => $backchannelLogoutSessionRequired,
            'consent_required' => $consentRequired,
            'owner_type' => $owner?->getMorphClass(),
            'owner_id' => $owner?->getKey(),
        ]);

        $client->secret = $authMethod->requiresSecret() ? ($secret ?? Str::random(40)) : null;
        $client->save();

        return $client;
    }
}
