<?php

declare(strict_types=1);

use Illuminate\Support\Facades\File;
use Lock\Server\Clients\Models\Client;

function installSelfEnv(string $contents = "APP_NAME=Testing\n"): string
{
    $directory = temporaryTestDirectory('install-self');
    File::put($directory.'/.env', $contents);
    app()->useEnvironmentPath($directory);

    return $directory.'/.env';
}

it('provisions the first-party client and writes both env halves', function (): void {
    $env = installSelfEnv();
    config(['oidc-client' => [], 'app.url' => 'https://app.test', 'oidc.issuer' => null, 'oidc.realm' => 'admin']);

    $this->artisan('oidc:install-self', ['--force' => true])->assertSuccessful();

    $client = Client::query()->where('provisioning_key', 'first-party')->firstOrFail();
    $clientId = (string) $client->getKey();
    $contents = (string) File::get($env);

    expect($contents)
        ->toContain('OIDC_FIRST_PARTY_CLIENT='.$clientId)
        ->toContain('OIDC_FIRST_PARTY_TRUSTED=true')
        ->toContain('OIDC_RP_ENABLED=true')
        ->toContain("OIDC_RP_ISSUER=https://app.test\n")
        ->toContain('OIDC_RP_CLIENT_ID='.$clientId)
        ->toContain('OIDC_RP_REDIRECT_URI=https://app.test/login/callback')
        ->toContain('OIDC_RP_POST_LOGOUT_REDIRECT_URI=https://app.test')
        ->toContain('OIDC_ISSUER=https://app.test')
        ->and(preg_match('/^OIDC_RP_CLIENT_SECRET=.+$/m', $contents))->toBe(1);
});

it('forwards configured provisioning options to the first-party client', function (): void {
    installSelfEnv();
    config([
        'oidc-client' => [],
        'app.url' => 'https://app.test',
        'oidc.install_self' => [
            'redirect_uris' => ['https://app.test/other/callback'],
            'post_logout_redirect_uris' => ['https://app.test/goodbye'],
            'allowed_exchange_audiences' => ['https://api.test'],
        ],
    ]);

    $this->artisan('oidc:install-self', ['--force' => true])->assertSuccessful();

    $client = Client::query()->where('provisioning_key', 'first-party')->firstOrFail();

    expect($client->getAttribute('redirect_uris'))->toBe(['https://app.test/login/callback', 'https://app.test/other/callback'])
        ->and(json_decode((string) $client->getRawOriginal('post_logout_redirect_uris'), true))
        ->toBe(['https://app.test', 'https://app.test/goodbye'])
        ->and(json_decode((string) $client->getRawOriginal('allowed_exchange_audiences'), true))
        ->toBe(['https://api.test'])
        ->and($client->getAttribute('grant_types'))->toContain('urn:ietf:params:oauth:grant-type:token-exchange');
});

it('adopts the existing client on a second run instead of minting a new one', function (): void {
    $env = installSelfEnv();
    config(['oidc-client' => [], 'app.url' => 'https://app.test']);

    $this->artisan('oidc:install-self', ['--force' => true])->assertSuccessful();

    $firstContents = (string) File::get($env);
    preg_match('/^OIDC_RP_CLIENT_SECRET=(.+)$/m', $firstContents, $secret);
    preg_match('/^OIDC_FIRST_PARTY_CLIENT=(.+)$/m', $firstContents, $clientId);

    $this->artisan('oidc:install-self', ['--force' => true])->assertSuccessful();

    $secondContents = (string) File::get($env);

    expect(Client::query()->count())->toBe(1)
        ->and($secondContents)->toContain('OIDC_FIRST_PARTY_CLIENT='.$clientId[1])
        ->and($secondContents)->toContain('OIDC_RP_CLIENT_SECRET='.$secret[1]);
});

it('rotates the client secret when run again with --fresh', function (): void {
    $env = installSelfEnv();
    config(['oidc-client' => [], 'app.url' => 'https://app.test']);

    $this->artisan('oidc:install-self', ['--force' => true])->assertSuccessful();

    preg_match('/^OIDC_RP_CLIENT_SECRET=(.+)$/m', (string) File::get($env), $secret);
    $clientId = (string) Client::query()->firstOrFail()->getKey();

    $this->artisan('oidc:install-self', ['--force' => true, '--fresh' => true])->assertSuccessful();

    $contents = (string) File::get($env);
    preg_match('/^OIDC_RP_CLIENT_SECRET=(.+)$/m', $contents, $rotated);

    expect(Client::query()->count())->toBe(1)
        ->and($contents)->toContain('OIDC_FIRST_PARTY_CLIENT='.$clientId)
        ->and($rotated[1])->not->toBe($secret[1]);
});

it('fails instead of rotating when the configured secret no longer matches', function (): void {
    $env = installSelfEnv();
    config(['oidc-client' => [], 'app.url' => 'https://app.test']);

    $this->artisan('oidc:install-self', ['--force' => true])->assertSuccessful();
    $storedSecret = Client::query()->sole()->getRawOriginal('secret');

    File::put($env, (string) preg_replace(
        '/^OIDC_RP_CLIENT_SECRET=.+$/m',
        'OIDC_RP_CLIENT_SECRET=tampered',
        (string) File::get($env),
    ));

    $this->artisan('oidc:install-self', ['--force' => true])->assertFailed();

    expect(Client::query()->sole()->getRawOriginal('secret'))->toBe($storedSecret);
});

it('fails when the relying-party package is not installed', function (): void {
    $env = installSelfEnv();
    $before = File::get($env);
    config(['oidc-client' => null, 'app.url' => 'https://app.test']);

    $this->artisan('oidc:install-self', ['--force' => true])->assertFailed();

    expect(File::get($env))->toBe($before);
});

it('installs a first-party client per realm and leaves the other realms alone', function (): void {
    installSelfEnv();
    config(['oidc-client' => [], 'app.url' => 'https://app.test', 'oidc.realm' => 'admin']);
    $this->artisan('oidc:install-self', ['--force' => true])->assertSuccessful();
    $admin = Client::query()->sole();
    $adminAttributes = $admin->getAttributes();

    config(['oidc.realm' => 'partners']);
    $this->artisan('oidc:install-self', ['--force' => true, '--fresh' => true])->assertSuccessful();

    expect($admin->refresh()->getAttributes())->toBe($adminAttributes)
        ->and(Client::query()->where('realm', 'partners')->sole()->getRawOriginal('provisioning_key'))
        ->toBe('first-party');
});
