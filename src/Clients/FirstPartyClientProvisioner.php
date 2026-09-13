<?php

declare(strict_types=1);

namespace Lock\Server\Clients;

use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Lock\Server\Clients\Events\ClientProvisioned;
use Lock\Server\Clients\Models\Client;
use Lock\Server\Shared\Clients\ClientProvisioner;
use Lock\Server\Shared\Clients\FirstPartyClientProvisioningException;
use Lock\Server\Shared\Clients\ProvisionedClient;
use SensitiveParameter;

final readonly class FirstPartyClientProvisioner implements ClientProvisioner
{
    private const string ProvisioningKey = 'first-party';

    private const string TokenExchangeGrant = 'urn:ietf:params:oauth:grant-type:token-exchange';

    public function __construct(private ClientRepository $clients) {}

    /**
     * @param  string[]  $redirectUris
     * @param  string[]  $postLogoutRedirectUris
     * @param  string[]  $allowedExchangeAudiences
     * @param  string[]|null  $defaultScopes  overrides the realm's default scopes; null keeps what the client has
     * @param  string[]|null  $optionalScopes  overrides the realm's optional scopes; null keeps what the client has
     */
    public function provision(
        string $name,
        array $redirectUris,
        array $postLogoutRedirectUris = [],
        array $allowedExchangeAudiences = [],
        ?string $adoptClientId = null,
        bool $rotateSecret = false,
        #[SensitiveParameter] ?string $existingClientSecret = null,
        ?array $defaultScopes = null,
        ?array $optionalScopes = null,
    ): ProvisionedClient {
        $name = trim($name);
        $redirectUris = $this->normalizeUris($redirectUris, 'redirect URI');
        $postLogoutRedirectUris = $this->normalizeUris($postLogoutRedirectUris, 'post-logout redirect URI');
        $allowedExchangeAudiences = $this->normalizeAudiences($allowedExchangeAudiences);
        $scopes = [
            ...($defaultScopes === null ? [] : ['default_scopes' => $this->normalizeScopes($defaultScopes)]),
            ...($optionalScopes === null ? [] : ['optional_scopes' => $this->normalizeScopes($optionalScopes)]),
        ];

        if ($name === '') {
            throw new FirstPartyClientProvisioningException('The first-party client name must not be empty.');
        }

        if ($redirectUris === []) {
            throw new FirstPartyClientProvisioningException('At least one redirect URI is required.');
        }

        if ($allowedExchangeAudiences !== [] && ! config('oidc.clients.token_exchange', true)) {
            throw new FirstPartyClientProvisioningException('Token exchange audiences cannot be configured while token exchange is disabled.');
        }

        try {
            return $this->recordProvisioned($this->transactionalProvision(
                $name,
                $redirectUris,
                $postLogoutRedirectUris,
                $allowedExchangeAudiences,
                $scopes,
                $adoptClientId,
                $rotateSecret,
                $existingClientSecret,
            ));
        } catch (QueryException $exception) {
            if ($this->isUniqueConstraint($exception)
                && Client::query()->inRealm()->where('provisioning_key', self::ProvisioningKey)->exists()) {
                return $this->recordProvisioned($this->transactionalProvision(
                    $name,
                    $redirectUris,
                    $postLogoutRedirectUris,
                    $allowedExchangeAudiences,
                    $scopes,
                    $adoptClientId,
                    $rotateSecret,
                    $existingClientSecret,
                ));
            }

            throw $exception;
        }
    }

    public function rollback(ProvisionedClient $result): void
    {
        if ($result->wasCreated) {
            $this->clients->delete($result->client->key, $result->client->realm);
        }
    }

    private function recordProvisioned(ProvisionedClient $result): ProvisionedClient
    {
        event(new ClientProvisioned($result->client->clientId, created: $result->wasCreated, secretRotated: $result->secretRotated, realm: $result->client->realm));

        return $result;
    }

    /**
     * @param  string[]  $redirectUris
     * @param  string[]  $postLogoutRedirectUris
     * @param  string[]  $allowedExchangeAudiences
     * @param  array{default_scopes?: string[], optional_scopes?: string[]}  $scopes
     */
    private function transactionalProvision(
        string $name,
        array $redirectUris,
        array $postLogoutRedirectUris,
        array $allowedExchangeAudiences,
        array $scopes,
        ?string $adoptClientId,
        bool $rotateSecret,
        #[SensitiveParameter] ?string $existingClientSecret,
    ): ProvisionedClient {
        return DB::transaction(function () use (
            $name,
            $redirectUris,
            $postLogoutRedirectUris,
            $allowedExchangeAudiences,
            $scopes,
            $adoptClientId,
            $rotateSecret,
            $existingClientSecret,
        ): ProvisionedClient {
            $client = Client::query()
                ->inRealm()
                ->where('provisioning_key', self::ProvisioningKey)
                ->lockForUpdate()
                ->first();

            $created = false;

            if ($client !== null
                && $adoptClientId !== null
                && $client->client_id !== $adoptClientId) {
                throw new FirstPartyClientProvisioningException('A different client already owns the first-party provisioning key.');
            }

            if ($client === null && $adoptClientId !== null) {
                $client = Client::query()->inRealm()->where('client_id', $adoptClientId)->lockForUpdate()->first();

                if ($client === null) {
                    throw new FirstPartyClientProvisioningException("The adoption client [{$adoptClientId}] does not exist.");
                }
            }

            if ($client === null) {
                $client = $this->clients->createAuthorizationCodeGrantClient($name, $redirectUris);
                $created = true;
            }

            $this->assertEligible($client);

            if (! $created
                && $existingClientSecret !== null
                && ! hash_equals((string) $client->secret, $existingClientSecret)) {
                throw new FirstPartyClientProvisioningException('The existing first-party client secret does not match.');
            }

            $grantTypes = ['authorization_code', 'refresh_token'];

            if ($allowedExchangeAudiences !== []) {
                $grantTypes[] = self::TokenExchangeGrant;
            }

            $client->forceFill([
                'name' => $name,
                'redirect_uris' => $redirectUris,
                'post_logout_redirect_uris' => $postLogoutRedirectUris,
                'allowed_exchange_audiences' => $allowedExchangeAudiences,
                'grant_types' => $grantTypes,
                'provisioning_key' => self::ProvisioningKey,
                ...$scopes,
            ])->save();

            if ($rotateSecret) {
                $this->clients->regenerateSecret($client);
            }

            $secret = $created || $rotateSecret ? $client->secret : $existingClientSecret;

            return new ProvisionedClient(
                client: $client->refresh()->snapshot(),
                clientSecret: $secret,
                wasCreated: $created,
                secretRotated: $rotateSecret,
            );
        });
    }

    private function assertEligible(Client $client): void
    {
        if ($client->revoked_at !== null) {
            throw new FirstPartyClientProvisioningException('The first-party client is revoked.');
        }

        if (empty($client->getAttributes()['secret'] ?? null)) {
            throw new FirstPartyClientProvisioningException('The first-party client must be confidential.');
        }

        if ($client->owner_id !== null) {
            throw new FirstPartyClientProvisioningException('The first-party client must not be owned by a user.');
        }
    }

    private function isUniqueConstraint(QueryException $exception): bool
    {
        $sqlState = $exception->errorInfo[0] ?? null;

        return is_string($sqlState) && in_array($sqlState, ['23000', '23505'], true);
    }

    /**
     * @param  mixed[]  $values
     * @return string[]
     */
    private function normalizeUris(array $values, string $label): array
    {
        return $this->normalize($values, function (string $value) use ($label): void {
            $parts = parse_url($value);

            if (preg_match('/[\x00-\x20\x7F\\\\]|%(?![0-9A-Fa-f]{2})/', $value) === 1
                || filter_var($value, FILTER_VALIDATE_URL) === false
                || ! is_array($parts)
                || ! in_array(strtolower((string) ($parts['scheme'] ?? '')), ['http', 'https'], true)
                || ! is_string($parts['host'] ?? null)
                || $parts['host'] === ''
                || isset($parts['user'])
                || isset($parts['pass'])
                || array_key_exists('fragment', $parts)) {
                throw new FirstPartyClientProvisioningException("The {$label} [{$value}] must be an absolute HTTP(S) URI without user information or a fragment.");
            }
        });
    }

    /**
     * @param  mixed[]  $values
     * @return string[]
     */
    private function normalizeAudiences(array $values): array
    {
        return $this->normalize($values, function (string $value): void {
            if (! str_starts_with(strtolower($value), 'urn:') && ! $this->isHttpUrl($value)) {
                throw new FirstPartyClientProvisioningException("The audience [{$value}] must be an HTTP(S) URL or a urn: identifier.");
            }
        });
    }

    /**
     * @param  mixed[]  $values
     * @return string[]
     */
    private function normalizeScopes(array $values): array
    {
        return $this->normalize($values, static function (): void {});
    }

    private function isHttpUrl(string $value): bool
    {
        $parts = parse_url($value);

        return is_array($parts)
            && in_array(strtolower((string) ($parts['scheme'] ?? '')), ['http', 'https'], true)
            && is_string($parts['host'] ?? null)
            && $parts['host'] !== '';
    }

    /**
     * @param  mixed[]  $values
     * @param  callable(string): void  $validate
     * @return string[]
     */
    private function normalize(array $values, callable $validate): array
    {
        $normalized = [];

        foreach ($values as $value) {
            if (! is_string($value) || trim($value) === '') {
                throw new FirstPartyClientProvisioningException('Provisioning metadata values must be non-empty strings.');
            }

            $value = trim($value);
            $validate($value);
            $normalized[$value] = $value;
        }

        return array_values($normalized);
    }
}
