<?php

declare(strict_types=1);

namespace Lock\Server\Clients\Models;

use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use Lock\Server\Database\Factories\ClientFactory;
use Lock\Server\Shared\Clients\Client as ClientSnapshot;
use Lock\Server\Shared\Clients\TokenEndpointAuthMethod;
use Lock\Server\Shared\Realms\BelongsToRealm;

/**
 * @property string $id
 * @property string $realm
 * @property string $client_id
 * @property string $name
 * @property ?string $secret
 * @property TokenEndpointAuthMethod $token_endpoint_auth_method
 * @property array<int, string> $redirect_uris
 * @property array<int, string> $post_logout_redirect_uris
 * @property array<int, string> $grant_types
 * @property array<int, string> $default_scopes
 * @property array<int, string> $optional_scopes
 * @property array<int, string> $allowed_exchange_audiences
 * @property ?string $backchannel_logout_uri
 * @property bool $backchannel_logout_session_required
 * @property bool $consent_required
 * @property ?string $provisioning_key
 * @property ?CarbonInterface $revoked_at
 * @property ?string $owner_type
 * @property ?string $owner_id
 */
class Client extends Model
{
    use BelongsToRealm, HasUuids;

    /** @use HasFactory<ClientFactory> */
    use HasFactory;

    protected $table = 'oidc_clients';

    protected $guarded = [];

    /**
     * The secret is encrypted at rest, so it stays readable for an admin UI or
     * API; hiding it keeps it out of incidental serialization all the same.
     */
    protected $hidden = ['secret'];

    protected static function newFactory(): ClientFactory
    {
        return ClientFactory::new();
    }

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'redirect_uris' => 'array',
            'post_logout_redirect_uris' => 'array',
            'grant_types' => 'array',
            'secret' => 'encrypted',
            'token_endpoint_auth_method' => TokenEndpointAuthMethod::class,
            'default_scopes' => 'array',
            'optional_scopes' => 'array',
            'allowed_exchange_audiences' => 'array',
            'backchannel_logout_session_required' => 'bool',
            'consent_required' => 'bool',
            'revoked_at' => 'datetime',
        ];
    }

    /** @return MorphTo<Model, $this> */
    public function owner(): MorphTo
    {
        return $this->morphTo('owner');
    }

    public function snapshot(): ClientSnapshot
    {
        return new ClientSnapshot(
            key: $this->id,
            clientId: $this->client_id,
            realm: $this->realm,
            name: $this->name,
            authMethod: $this->token_endpoint_auth_method,
            redirectUris: array_values($this->redirect_uris ?? []),
            postLogoutRedirectUris: array_values($this->post_logout_redirect_uris ?? []),
            grantTypes: array_values($this->grant_types ?? []),
            defaultScopeAssignments: array_values($this->default_scopes ?? []),
            optionalScopeAssignments: array_values($this->optional_scopes ?? []),
            allowedAudiences: array_values(array_filter($this->allowed_exchange_audiences ?? [], is_string(...))),
            backchannelLogoutUri: $this->backchannel_logout_uri,
            backchannelLogoutSessionRequired: $this->backchannel_logout_session_required ?? false,
            consentRequired: $this->consent_required ?? true,
            confidential: ! empty($this->getAttributes()['secret'] ?? null),
            revoked: $this->revoked_at !== null,
        );
    }
}
