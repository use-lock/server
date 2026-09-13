<?php

declare(strict_types=1);

use Lock\Server\Clients\ClientRepository;
use Lock\Server\Tokens\Exchange\TokenExchanger;

it('rejects an invalid subject token with invalid_grant', function (): void {
    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('App', ['https://app.test/cb']);
    $client->forceFill(['allowed_exchange_audiences' => ['https://api.orders.test']])->save();

    expectExchangeDenied(
        fn () => app(TokenExchanger::class)->exchange('garbage', $client->snapshot(), 'https://api.orders.test', ['openid']),
        'invalid_grant',
    );
});
