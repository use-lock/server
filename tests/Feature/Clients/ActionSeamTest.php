<?php

declare(strict_types=1);

use Lock\Server\Clients\Actions\RegisterClient;
use Lock\Server\Shared\Clients\RegisterClient as RegistersClients;
use Lock\Server\Shared\Clients\RegisteredClient;

final readonly class RegisterClientWithApproval extends RegisterClient
{
    public function __invoke(array $metadata): RegisteredClient
    {
        return parent::__invoke([...$metadata, 'client_name' => 'Approved by the host']);
    }
}

it('lets an application replace a domain action by binding over its name', function (): void {
    config(['oidc.clients.registration' => [
        'enabled' => true,
        'allowed_redirect_schemes' => [],
        'allowed_redirect_domains' => ['*'],
    ]]);
    reloadOidcRoutes();

    app()->bind(RegistersClients::class, RegisterClientWithApproval::class);

    $this->postJson('/oauth/register', ['redirect_uris' => ['https://rp.test/cb']])
        ->assertCreated()
        ->assertJsonPath('client_name', 'Approved by the host');
});
