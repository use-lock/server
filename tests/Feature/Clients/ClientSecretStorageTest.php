<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Crypt;
use Lock\Server\Clients\ClientRepository;
use Lock\Server\Clients\Models\Client;

it('keeps a client secret readable after a reload', function (): void {
    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/callback']);
    $issued = $client->secret;

    expect($issued)->toBeString()->toHaveLength(40)
        ->and(Client::query()->find($client->getKey())->secret)->toBe($issued);
});

it('stores the secret encrypted rather than in the clear', function (): void {
    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/callback']);

    $stored = (string) $client->getRawOriginal('secret');

    expect($stored)->not->toBe($client->secret)
        ->and(Crypt::decryptString($stored))->toBe($client->secret);
});

it('rotates to a new readable secret', function (): void {
    $clients = app(ClientRepository::class);
    $client = $clients->createAuthorizationCodeGrantClient('RP', ['https://rp.test/callback']);
    $before = $client->secret;

    $clients->regenerateSecret($client);

    expect($client->secret)->not->toBe($before)
        ->and(Client::query()->find($client->getKey())->secret)->toBe($client->secret);
});

it('leaves a public client without a secret', function (): void {
    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/callback'], confidential: false);

    expect($client->secret)->toBeNull()
        ->and($client->snapshot()->confidential)->toBeFalse();
});

it('keeps the secret out of the serialized client', function (): void {
    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/callback']);

    expect($client->toArray())->not->toHaveKey('secret');
});
