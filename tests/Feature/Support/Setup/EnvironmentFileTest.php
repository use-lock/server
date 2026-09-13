<?php

declare(strict_types=1);

use Lock\Server\Support\Setup\EnvironmentFile;
use Lock\Server\Support\Setup\EnvironmentWriteException;

function environmentFileFixture(string $contents): string
{
    $path = temporaryTestDirectory('envfile').'/.env';
    file_put_contents($path, $contents);

    return $path;
}

it('upserts an existing key and appends a new one in a single write', function (): void {
    $path = environmentFileFixture("APP_NAME=Testing\nOIDC_FIRST_PARTY_CLIENT=stale\n");

    new EnvironmentFile($path)->write([
        'OIDC_FIRST_PARTY_CLIENT' => 'abc-123',
        'OIDC_FIRST_PARTY_TRUSTED' => 'true',
    ]);

    $contents = (string) file_get_contents($path);

    expect(substr_count($contents, 'OIDC_FIRST_PARTY_CLIENT='))->toBe(1)
        ->and($contents)->toContain('OIDC_FIRST_PARTY_CLIENT=abc-123')
        ->and($contents)->toContain('OIDC_FIRST_PARTY_TRUSTED=true')
        ->and($contents)->toContain('APP_NAME=Testing');
});

it('replaces the target atomically, keeping its permissions and leaving no temp file behind', function (): void {
    $path = environmentFileFixture("APP_NAME=Testing\n");
    chmod($path, 0600);

    new EnvironmentFile($path)->write(['OIDC_PRIVATE_KEY' => 'secret']);

    expect(glob(dirname($path).'/*.tmp') ?: [])->toBe([])
        ->and(fileperms($path) & 0777)->toBe(0600)
        ->and((string) file_get_contents($path))->toContain('OIDC_PRIVATE_KEY=secret');
});

it('throws when the environment file cannot be read and reads null when it does not exist', function (): void {
    expect(new EnvironmentFile('/nonexistent/dir/.env')->value('APP_NAME'))->toBeNull()
        ->and(fn () => new EnvironmentFile('/nonexistent/dir/.env')->write(['A' => 'b']))->toThrow(EnvironmentWriteException::class);
});

it('reads plain, quoted and commented values and returns null for empty or absent keys', function (): void {
    $path = environmentFileFixture(implode("\n", [
        'APP_NAME=Testing',
        "SINGLE='with spaces'",
        'DOUBLE="quo # ted"',
        '# OIDC_ISSUER=commented',
        'OIDC_ISSUER=https://op.test # the provider',
        'EMPTY=',
        '',
    ]));
    $store = new EnvironmentFile($path);

    expect($store->value('APP_NAME'))->toBe('Testing')
        ->and($store->value('SINGLE'))->toBe('with spaces')
        ->and($store->value('DOUBLE'))->toBe('quo # ted')
        ->and($store->value('OIDC_ISSUER'))->toBe('https://op.test')
        ->and($store->value('EMPTY'))->toBeNull()
        ->and($store->value('MISSING'))->toBeNull();
});
