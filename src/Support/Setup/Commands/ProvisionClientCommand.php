<?php

declare(strict_types=1);

namespace Lock\Server\Support\Setup\Commands;

use Illuminate\Console\Command;
use Lock\Server\Shared\Clients\ClientProvisioner;
use Lock\Server\Shared\Clients\FirstPartyClientProvisioningException;
use Lock\Server\Support\Setup\EnvironmentFile;
use Lock\Server\Support\Setup\EnvironmentWriteException;

class ProvisionClientCommand extends Command
{
    protected $signature = 'oidc:client
        {--first-party : Provision the package-managed first-party client}
        {--name= : Client display name}
        {--redirect-uri=* : Registered authorization callback URI}
        {--post-logout-redirect-uri=* : Registered post-logout redirect URI}
        {--audience=* : Allowed token-exchange audience}
        {--default-scope=* : Scope granted without being requested; overrides the realm default}
        {--optional-scope=* : Scope granted on request, * for every catalog scope; overrides the realm default}
        {--trusted : Skip consent for this first-party client}
        {--adopt= : Adopt the existing client with this client_id}
        {--rotate : Rotate the client secret explicitly}
        {--write-env : Write provider client ID and trusted state to .env}';

    protected $description = 'Provision the package-managed first-party OIDC client';

    public function __construct(
        private readonly ClientProvisioner $provisioner,
        private readonly EnvironmentFile $environment,
    ) {
        parent::__construct();
    }

    public function handle(): int
    {
        if (! $this->option('first-party')) {
            $this->error('The --first-party option is required.');

            return self::INVALID;
        }

        $name = $this->stringOption('name');
        $redirectUris = $this->arrayOption('redirect-uri');

        if ($this->input->isInteractive()) {
            $name ??= $this->ask('Client name');

            if ($redirectUris === []) {
                $answer = $this->ask('Redirect URIs (comma separated)');
                $redirectUris = is_string($answer) ? $this->commaSeparated($answer) : [];
            }
        }

        if ($name === null || trim($name) === '') {
            $this->error('The --name option is required when running non-interactively.');

            return self::INVALID;
        }

        if ($redirectUris === []) {
            $this->error('At least one --redirect-uri option is required when running non-interactively.');

            return self::INVALID;
        }

        try {
            $result = $this->provisioner->provision(
                name: $name,
                redirectUris: $redirectUris,
                postLogoutRedirectUris: $this->arrayOption('post-logout-redirect-uri'),
                allowedExchangeAudiences: $this->arrayOption('audience'),
                adoptClientId: $this->stringOption('adopt'),
                rotateSecret: (bool) $this->option('rotate'),
                defaultScopes: $this->arrayOption('default-scope') ?: null,
                optionalScopes: $this->arrayOption('optional-scope') ?: null,
            );
        } catch (FirstPartyClientProvisioningException $exception) {
            $this->error($exception->getMessage());

            return self::FAILURE;
        }

        $trusted = (bool) $this->option('trusted');

        $this->line('OIDC_FIRST_PARTY_CLIENT='.$result->client->clientId);
        $this->line('OIDC_FIRST_PARTY_TRUSTED='.($trusted ? 'true' : 'false'));

        if ($result->clientSecret !== null) {
            $this->line('OIDC_CLIENT_ID='.$result->client->clientId);
            $this->line('OIDC_CLIENT_SECRET='.$result->clientSecret);
        }

        if (! $this->option('write-env')) {
            return self::SUCCESS;
        }

        if ($this->input->isInteractive()
            && ! $this->confirm('Write OIDC_FIRST_PARTY_CLIENT and OIDC_FIRST_PARTY_TRUSTED to .env?')) {
            $this->info('Credentials were not written to .env.');

            return self::SUCCESS;
        }

        try {
            $this->environment->write([
                'OIDC_FIRST_PARTY_CLIENT' => $result->client->clientId,
                'OIDC_FIRST_PARTY_TRUSTED' => $trusted ? 'true' : 'false',
            ]);
        } catch (EnvironmentWriteException $exception) {
            $this->error($exception->getMessage());

            return self::FAILURE;
        }

        return self::SUCCESS;
    }

    private function stringOption(string $name): ?string
    {
        $value = $this->option($name);

        return is_string($value) ? $value : null;
    }

    /** @return string[] */
    private function arrayOption(string $name): array
    {
        $value = $this->option($name);

        return is_array($value) ? $value : [];
    }

    /** @return string[] */
    private function commaSeparated(string $value): array
    {
        return array_values(array_filter(
            array_map(trim(...), explode(',', $value)),
            static fn (string $item): bool => $item !== '',
        ));
    }
}
