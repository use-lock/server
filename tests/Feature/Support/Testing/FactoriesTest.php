<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Hash;
use Lock\Server\Clients\ClientRepository;
use Lock\Server\Shared\Realms\CurrentRealm;
use Lock\Server\Tokens\Models\AccessToken;
use Workbench\App\Models\User;

it('issues a row to a client inside the client\'s realm', function (): void {
    $client = CurrentRealm::runAs('acme', fn () => app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/cb']));
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('secret')]);

    $token = AccessToken::factory()->forClient($client)->forUser($user)->create();

    expect($token->only('realm', 'client_id', 'user_id'))->toBe([
        'realm' => 'acme',
        'client_id' => $client->getKey(),
        'user_id' => $user->getKey(),
    ]);
});
