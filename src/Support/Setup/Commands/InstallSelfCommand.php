<?php

declare(strict_types=1);

namespace Lock\Server\Support\Setup\Commands;

use Illuminate\Console\Command;
use Lock\Server\Shared\Clients\ClientProvisioner;
use Lock\Server\Shared\Clients\FirstPartyClientProvisioningException;
use Lock\Server\Shared\Realms\IssuerResolver;
use Lock\Server\SigningKeys\SigningKeyGenerator;
use Lock\Server\Support\Setup\EnvironmentFile;
use Lock\Server\Support\Setup\EnvironmentWriteException;

class InstallSelfCommand extends Command
{
    protected $signature = 'oidc:install-self
        {--name= : First-party client display name (defaults to the app name)}
        {--fresh : Rotate the first-party client secret instead of adopting the configured one}
        {--force : Skip the confirmation prompt}';

    protected $description = 'Configure this app as its own OIDC provider and relying party (self-SSO)';

    public function __construct(
        private readonly ClientProvisioner $provisioner,
        private readonly EnvironmentFile $environment,
        private readonly SigningKeyGenerator $keys,
        private readonly IssuerResolver $issuers,
    ) {
        parent::__construct();
    }

    public function handle(): int
    {
        if (! is_array(config('oidc-client'))) {
            $this->error('The relying-party package is not installed. Run `composer require use-lock/client-laravel` first.');

            return self::FAILURE;
        }

        $appUrl = rtrim((string) config('app.url'), '/');

        if ($appUrl === '') {
            $this->error('APP_URL must be set before configuring self-SSO.');

            return self::FAILURE;
        }

        $nameOption = $this->option('name');
        $name = is_string($nameOption) && $nameOption !== '' ? $nameOption : $this->defaultClientName();
        $redirectUri = $appUrl.'/login/callback';

        $issuer = $this->issuers->url();

        if (! $this->option('force')
            && $this->input->isInteractive()
            && ! $this->confirm("Provision the first-party client and write self-SSO configuration to .env for {$appUrl}?")) {
            $this->info('Aborted.');

            return self::SUCCESS;
        }

        $fresh = (bool) $this->option('fresh');
        $adoptClientId = $fresh ? null : $this->configuredClientId();

        try {
            $result = $this->provisioner->provision(
                name: $name,
                redirectUris: [$redirectUri, ...$this->configuredProvisionList('redirect_uris')],
                postLogoutRedirectUris: [$appUrl, ...$this->configuredProvisionList('post_logout_redirect_uris')],
                allowedExchangeAudiences: $this->configuredProvisionList('allowed_exchange_audiences'),
                adoptClientId: $adoptClientId,
                rotateSecret: $fresh,
                existingClientSecret: $fresh ? null : $this->environment->value('OIDC_CLIENT_SECRET'),
            );
        } catch (FirstPartyClientProvisioningException $exception) {
            $this->error($exception->getMessage());

            return self::FAILURE;
        }

        // The provider and the client read the same OIDC_ISSUER: for self-SSO
        // the client's realm is this app's own.
        $variables = [
            'OIDC_ISSUER' => $issuer,
            'OIDC_FIRST_PARTY_CLIENT' => $result->client->clientId,
            'OIDC_FIRST_PARTY_TRUSTED' => 'true',
            'OIDC_ENABLED' => 'true',
            'OIDC_CLIENT_ID' => $result->client->clientId,
            'OIDC_REDIRECT_URI' => $redirectUri,
            'OIDC_POST_LOGOUT_REDIRECT_URI' => $appUrl,
        ];

        if ($result->clientSecret !== null) {
            $variables['OIDC_CLIENT_SECRET'] = $result->clientSecret;
        }

        try {
            $this->environment->write($variables);
        } catch (EnvironmentWriteException $exception) {
            $this->provisioner->rollback($result);
            $this->error($exception->getMessage());

            return self::FAILURE;
        }

        $this->info('Self-SSO configured. First-party client: '.$result->client->clientId);

        if (! $this->keys->hasKeys()) {
            $this->warn('No signing keys found. Run `php artisan oidc:rotate-keys` to generate them.');
        }

        $this->warn('Restart the app (and any queue workers) so the new configuration takes effect.');

        return self::SUCCESS;
    }

    private function configuredClientId(): ?string
    {
        $clientId = $this->environment->value('OIDC_FIRST_PARTY_CLIENT')
            ?? config('oidc.clients.first_party.client_id');

        return is_string($clientId) && $clientId !== '' ? $clientId : null;
    }

    /** @return string[] */
    private function configuredProvisionList(string $key): array
    {
        return array_values(array_filter(
            (array) config("oidc.install_self.{$key}", []),
            fn (mixed $value): bool => is_string($value) && trim($value) !== '',
        ));
    }

    private function defaultClientName(): string
    {
        $appName = config('app.name');

        return is_string($appName) && $appName !== '' ? $appName : 'First-party app';
    }
}
