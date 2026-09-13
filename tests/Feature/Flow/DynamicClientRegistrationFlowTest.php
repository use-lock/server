<?php

declare(strict_types=1);

/**
 * RFC 7591 registration feeding the OAuth 2.1 §4.1 authorization code grant with RFC 7636 PKCE:
 * discovery → register → authorize → token → userinfo
 */

use Lock\Server\Clients\Models\Client;
use Lock\Server\Support\Testing\InteractsWithOidc;
use Workbench\App\Models\User;

uses(InteractsWithOidc::class);

it('lets a dynamically registered client complete the PKCE authorization code flow', function (): void {
    config(['oidc.clients.registration.enabled' => true]);
    reloadOidcRoutes();

    $registrationEndpoint = $this->getJson('/.well-known/openid-configuration')
        ->assertOk()
        ->json('registration_endpoint');

    $registration = $this->postJson($registrationEndpoint, [
        'client_name' => 'Agent',
        'redirect_uris' => ['https://agent.test/callback'],
    ])->assertCreated();

    $client = Client::query()->whereKey($registration->json('client_id'))->firstOrFail();
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'email_verified_at' => now(), 'password' => 'x']);

    fakeConsentViewUsing(fn (array $parameters) => response()->json(['authToken' => $parameters['authToken']]));

    $result = $this->authorizeAndApprove($user, $client, 'openid', ['redirect_uri' => 'https://agent.test/callback']);

    $result->response->assertOk();

    $this->withToken((string) $result->accessToken)->getJson('/oauth/userinfo')->assertOk();
});
