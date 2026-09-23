<?php

declare(strict_types=1);

namespace Lock\Server\Clients\Actions;

use InvalidArgumentException;
use Lock\Server\Clients\ClientRepository;
use Lock\Server\Clients\Events\ClientRegistered;
use Lock\Server\Shared\Clients\ClientRegistrationException;
use Lock\Server\Shared\Clients\RegisterClient as RegistersClients;
use Lock\Server\Shared\Clients\RegisteredClient;
use Lock\Server\Shared\Clients\TokenEndpointAuthMethod;
use Lock\Server\Shared\Http\PublicHttpEndpoint;
use Lock\Server\Shared\Realms\RealmResolver;

/**
 * RFC 7591 dynamic client registration of an authorization-code client.
 * Honoured metadata: `client_name`, `redirect_uris`, `token_endpoint_auth_method`,
 * `grant_types` and `response_types` (RFC 7591 §2), `post_logout_redirect_uris`
 * (OIDC RP-Initiated Logout 1.0 §3), `backchannel_logout_uri` and
 * `backchannel_logout_session_required` (OIDC Back-Channel Logout 1.0 §2.2).
 * A client registering `client_secret_basic` or `client_secret_post` is
 * confidential and receives a secret; `none` (the default) registers a public
 * client. Unknown fields are ignored (§2), since MCP clients routinely send
 * `application_type`, `software_id`, and similar. PKCE is enforced by the
 * grant for every client.
 */
readonly class RegisterClient implements RegistersClients
{
    protected const array GRANT_TYPES = ['authorization_code', 'refresh_token'];

    protected const array RESPONSE_TYPES = ['code'];

    public function __construct(
        protected ClientRepository $clients,
        protected RealmResolver $realms,
        protected PublicHttpEndpoint $endpoints,
    ) {}

    /**
     * @param  array<string, mixed>  $metadata  the RFC 7591 client metadata document
     *
     * @throws ClientRegistrationException
     */
    public function __invoke(array $metadata): RegisteredClient
    {
        $redirectUris = $this->normalizedUris($metadata['redirect_uris'] ?? null, 'redirect_uris', 'invalid_redirect_uri', required: true);
        $postLogoutRedirectUris = $this->normalizedUris($metadata['post_logout_redirect_uris'] ?? null, 'post_logout_redirect_uris', 'invalid_client_metadata', required: false);
        $authMethod = $this->tokenEndpointAuthMethod($metadata['token_endpoint_auth_method'] ?? null);
        $grantTypes = $this->grantTypes($metadata['grant_types'] ?? null);
        $this->assertResponseTypes($metadata['response_types'] ?? null);
        $backChannelLogoutUri = $this->backChannelLogoutUri($metadata['backchannel_logout_uri'] ?? null);

        $client = $this->clients->create(
            name: $this->clientName($metadata, $redirectUris),
            grantTypes: $grantTypes,
            redirectUris: $redirectUris,
            authMethod: $authMethod,
            postLogoutRedirectUris: $postLogoutRedirectUris,
            backchannelLogoutUri: $backChannelLogoutUri,
            backchannelLogoutSessionRequired: filter_var($metadata['backchannel_logout_session_required'] ?? false, FILTER_VALIDATE_BOOLEAN),
        );

        event(new ClientRegistered(
            clientId: $client->client_id,
            name: (string) $client->getAttribute('name'),
            redirectUris: $redirectUris,
            tokenEndpointAuthMethod: $authMethod->value,
            realm: $client->realm,
        ));

        return new RegisteredClient($client->snapshot(), $client->secret);
    }

    /**
     * @return list<string>
     */
    protected function normalizedUris(mixed $uris, string $field, string $error, bool $required): array
    {
        if ($uris === null && ! $required) {
            return [];
        }

        if (! is_array($uris) || ($uris === [] && $required)) {
            throw new ClientRegistrationException('invalid_client_metadata', $required
                ? 'At least one redirect URI is required.'
                : "The {$field} must be a list of URIs.");
        }

        $normalized = [];

        foreach ($uris as $uri) {
            if (! is_string($uri) || trim($uri) === '') {
                throw new ClientRegistrationException($error, "The {$field} must be non-empty strings.");
            }

            $uri = trim($uri);
            $rejection = $this->rejectRedirectUri($uri);

            if ($rejection !== null) {
                throw new ClientRegistrationException($error, $rejection);
            }

            $normalized[$uri] = $uri;
        }

        return array_values($normalized);
    }

    protected function tokenEndpointAuthMethod(mixed $method): TokenEndpointAuthMethod
    {
        if ($method === null) {
            return TokenEndpointAuthMethod::None;
        }

        $resolved = is_string($method) ? TokenEndpointAuthMethod::tryFrom($method) : null;

        return $resolved ?? throw new ClientRegistrationException(
            'invalid_client_metadata',
            'The token_endpoint_auth_method must be one of client_secret_basic, client_secret_post or none.',
        );
    }

    /**
     * RFC 7591 §2: the registered grant types must be ones this endpoint
     * provisions, and an authorization-code client without that grant could
     * never obtain a token.
     *
     * @return list<string>
     */
    protected function grantTypes(mixed $grantTypes): array
    {
        if ($grantTypes === null) {
            return self::GRANT_TYPES;
        }

        $strings = is_array($grantTypes) ? array_filter($grantTypes, is_string(...)) : [];
        $normalized = array_values(array_unique($strings));

        if ($normalized === []
            || ! is_array($grantTypes)
            || count($strings) !== count($grantTypes)
            || array_diff($normalized, self::GRANT_TYPES) !== []
            || ! in_array('authorization_code', $normalized, true)) {
            throw new ClientRegistrationException(
                'invalid_client_metadata',
                'The grant_types must include authorization_code and may only add refresh_token.',
            );
        }

        return $normalized;
    }

    protected function assertResponseTypes(mixed $responseTypes): void
    {
        if ($responseTypes === null) {
            return;
        }

        $normalized = is_array($responseTypes) ? array_values(array_unique(array_filter($responseTypes, is_string(...)))) : null;

        if ($normalized !== self::RESPONSE_TYPES) {
            throw new ClientRegistrationException('invalid_client_metadata', 'The response_types must be ["code"].');
        }
    }

    /** OIDC Back-Channel Logout 1.0 §2.2: an absolute https URL, which may carry port, path and query but no fragment. */
    protected function backChannelLogoutUri(mixed $uri): ?string
    {
        if ($uri === null) {
            return null;
        }

        $uri = is_string($uri) ? trim($uri) : null;

        try {
            $this->endpoints->validate($uri ?? '');
        } catch (InvalidArgumentException $exception) {
            throw new ClientRegistrationException('invalid_client_metadata', $exception->getMessage());
        }

        return $uri;
    }

    /**
     * @param  array<string, mixed>  $metadata
     * @param  list<string>  $redirectUris
     */
    protected function clientName(array $metadata, array $redirectUris): string
    {
        foreach (['client_name', 'name'] as $key) {
            $name = $metadata[$key] ?? null;

            if (is_string($name) && trim($name) !== '') {
                return trim($name);
            }
        }

        $host = parse_url($redirectUris[0], PHP_URL_HOST);

        return is_string($host) && $host !== '' ? $host : 'Dynamically Registered Client';
    }

    protected function rejectRedirectUri(string $uri): ?string
    {
        $parts = parse_url($uri);

        if (preg_match('/[\x00-\x20\x7F\\\\]|%(?![0-9A-Fa-f]{2})/', $uri) === 1
            || ! is_array($parts)
            || isset($parts['user'])
            || isset($parts['pass'])
            || array_key_exists('fragment', $parts)) {
            return "The redirect URI [{$uri}] must be an absolute URI without user information or a fragment.";
        }

        $scheme = strtolower((string) ($parts['scheme'] ?? ''));
        $host = strtolower((string) ($parts['host'] ?? ''));

        if ($scheme === '' || $host === '') {
            return "The redirect URI [{$uri}] must declare a scheme and a host.";
        }

        if (! in_array($scheme, ['http', 'https'], true)) {
            $schemes = $this->realms->current()->clients()->allowedRedirectSchemes;

            return in_array($scheme, array_map(strtolower(...), $schemes), true)
                ? null
                : "The redirect URI scheme [{$scheme}] is not allowed.";
        }

        $domains = $this->realms->current()->clients()->allowedRedirectDomains;

        if (in_array('*', $domains, true) || in_array($host, array_map(strtolower(...), $domains), true)) {
            return null;
        }

        return "The redirect URI host [{$host}] is not allowed.";
    }
}
