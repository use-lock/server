<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\File;
use Lock\Server\Clients\ClientRepository;
use Lock\Server\Clients\Models\Client;

function clientCommandEnv(string $contents = "APP_NAME=Testing\n"): string
{
    $directory = temporaryTestDirectory('client-command');
    File::put($directory.'/.env', $contents);
    app()->useEnvironmentPath($directory);

    return $directory.'/.env';
}

it('creates and prints first-party credentials without changing env', function (): void {
    $env = clientCommandEnv();
    $before = File::get($env);

    $exitCode = Artisan::call('oidc:client', [
        '--first-party' => true,
        '--name' => 'First-party app',
        '--redirect-uri' => ['https://app.test/login/callback', 'https://app.test/oauth/callback'],
        '--post-logout-redirect-uri' => ['https://app.test/logged-out', 'https://app.test/signed-out'],
        '--audience' => ['urn:example:orders', 'https://api.test/invoices'],
        '--no-interaction' => true,
    ]);
    $output = trim(Artisan::output());
    preg_match('/^OIDC_CLIENT_SECRET=(.+)$/m', $output, $secretMatch);
    $client = Client::query()->where('provisioning_key', 'first-party')->firstOrFail();
    $clientId = (string) $client->getKey();
    $plainSecret = $secretMatch[1] ?? null;

    expect($exitCode)->toBe(0)
        ->and($plainSecret)->toBeString()->not->toBeEmpty()
        ->and($output)->toBe(implode(PHP_EOL, [
            'OIDC_FIRST_PARTY_CLIENT='.$clientId,
            'OIDC_FIRST_PARTY_TRUSTED=false',
            'OIDC_CLIENT_ID='.$clientId,
            'OIDC_CLIENT_SECRET='.$plainSecret,
        ]))
        ->and($client->secret)->toBe($plainSecret)
        ->and($client->getAttribute('redirect_uris'))->toBe([
            'https://app.test/login/callback',
            'https://app.test/oauth/callback',
        ])
        ->and(json_decode((string) $client->getRawOriginal('post_logout_redirect_uris'), true, flags: JSON_THROW_ON_ERROR))->toBe([
            'https://app.test/logged-out',
            'https://app.test/signed-out',
        ])
        ->and(json_decode((string) $client->getRawOriginal('allowed_exchange_audiences'), true, flags: JSON_THROW_ON_ERROR))->toBe([
            'urn:example:orders',
            'https://api.test/invoices',
        ])
        ->and(File::get($env))->toBe($before);
});

it('reconciles without printing a secret and writes selected config explicitly', function (): void {
    $env = clientCommandEnv("APP_NAME=Testing\nOTHER=keep\n");
    $arguments = [
        '--first-party' => true,
        '--name' => 'First-party app',
        '--redirect-uri' => ['https://app.test/login/callback'],
        '--trusted' => true,
        '--write-env' => true,
        '--no-interaction' => true,
    ];

    $this->artisan('oidc:client', $arguments)->assertSuccessful();
    $this->artisan('oidc:client', $arguments)
        ->doesntExpectOutputToContain('OIDC_CLIENT_SECRET=')
        ->assertSuccessful();

    expect(File::get($env))->toContain('OIDC_FIRST_PARTY_CLIENT=')
        ->toContain('OIDC_FIRST_PARTY_TRUSTED=true')
        ->toContain('OTHER=keep');
});

it('prompts for required interactive values and confirms env writes', function (): void {
    $env = clientCommandEnv();

    $this->artisan('oidc:client', [
        '--first-party' => true,
        '--write-env' => true,
    ])->expectsQuestion('Client name', 'First-party app')
        ->expectsQuestion('Redirect URIs (comma separated)', 'https://app.test/login/callback')
        ->expectsConfirmation('Write OIDC_FIRST_PARTY_CLIENT and OIDC_FIRST_PARTY_TRUSTED to .env?', 'yes')
        ->assertSuccessful();

    expect(File::get($env))->toContain('OIDC_FIRST_PARTY_CLIENT=');
});

it('adopts an eligible client without printing its stored hash', function (): void {
    $env = clientCommandEnv();
    $client = app(ClientRepository::class)
        ->createAuthorizationCodeGrantClient('Legacy', ['https://legacy.test/callback']);
    $hash = (string) $client->getRawOriginal('secret');

    $this->artisan('oidc:client', [
        '--first-party' => true,
        '--name' => 'First-party app',
        '--redirect-uri' => ['https://app.test/login/callback'],
        '--adopt' => (string) $client->getKey(),
        '--no-interaction' => true,
    ])->doesntExpectOutputToContain($hash)
        ->doesntExpectOutputToContain('OIDC_CLIENT_SECRET=')
        ->assertSuccessful();

    expect(File::get($env))->toBe("APP_NAME=Testing\n")
        ->and($client->refresh()->getRawOriginal('provisioning_key'))->toBe('first-party');
});

it('leaves env unchanged after a provisioning failure', function (): void {
    $env = clientCommandEnv();
    $before = File::get($env);

    $this->artisan('oidc:client', [
        '--first-party' => true,
        '--name' => 'First-party app',
        '--redirect-uri' => ['not-a-uri'],
        '--write-env' => true,
        '--no-interaction' => true,
    ])->assertFailed();

    expect(File::get($env))->toBe($before);
});

it('requires explicit rotation before printing a replacement secret', function (): void {
    $base = [
        '--first-party' => true,
        '--name' => 'First-party app',
        '--redirect-uri' => ['https://app.test/login/callback'],
        '--no-interaction' => true,
    ];

    $this->artisan('oidc:client', $base)->assertSuccessful();
    $this->artisan('oidc:client', $base)
        ->doesntExpectOutputToContain('OIDC_CLIENT_SECRET=')
        ->assertSuccessful();
    $this->artisan('oidc:client', [...$base, '--rotate' => true])
        ->expectsOutputToContain('OIDC_CLIENT_SECRET=')
        ->assertSuccessful();
});

it('rejects invalid invocations with a usage exit code', function (array $arguments): void {
    $this->artisan('oidc:client', ['--no-interaction' => true, ...$arguments])->assertExitCode(2);

    expect(Client::query()->count())->toBe(0);
})->with([
    'without a mode' => [['--name' => 'First-party app', '--redirect-uri' => ['https://app.test/login/callback']]],
    'missing name' => [['--first-party' => true, '--redirect-uri' => ['https://app.test/login/callback']]],
    'missing redirect URI' => [['--first-party' => true, '--name' => 'First-party app']],
]);

it('does not write env when interactive confirmation is declined', function (): void {
    $env = clientCommandEnv();
    $before = File::get($env);

    $this->artisan('oidc:client', [
        '--first-party' => true,
        '--name' => 'First-party app',
        '--redirect-uri' => ['https://app.test/login/callback'],
        '--write-env' => true,
    ])->expectsConfirmation('Write OIDC_FIRST_PARTY_CLIENT and OIDC_FIRST_PARTY_TRUSTED to .env?', 'no')
        ->expectsOutput('Credentials were not written to .env.')
        ->assertSuccessful();

    expect(File::get($env))->toBe($before);
});

it('overrides the realm scope assignment with --default-scope and --optional-scope', function (): void {
    clientCommandEnv();

    Artisan::call('oidc:client', [
        '--first-party' => true,
        '--name' => 'App',
        '--redirect-uri' => ['https://app.test/login/callback'],
        '--default-scope' => ['openid'],
        '--optional-scope' => ['email', 'profile'],
        '--no-interaction' => true,
    ]);

    $client = Client::query()->where('provisioning_key', 'first-party')->firstOrFail()->snapshot();

    expect($client->defaultScopeAssignments)->toBe(['openid'])
        ->and($client->optionalScopeAssignments)->toBe(['email', 'profile']);
});

it('uses realm scope assignments when no scope options are supplied', function (): void {
    config(['oidc.clients.default_scopes' => ['openid'], 'oidc.clients.optional_scopes' => ['email']]);

    $this->artisan('oidc:client', [
        '--first-party' => true,
        '--name' => 'App',
        '--redirect-uri' => ['https://app.test/login/callback'],
        '--no-interaction' => true,
    ])->assertSuccessful();

    $client = Client::query()->where('provisioning_key', 'first-party')->firstOrFail();

    expect($client->default_scopes)->toBe(['openid'])
        ->and($client->optional_scopes)->toBe(['email']);
});
