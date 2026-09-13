<?php

declare(strict_types=1);

/**
 * OAuth 2.1 §4.2 (client credentials grant); RFC 8707 §2 (resource indicators); RFC 9068 §2.2 (aud, client_id)
 */

use Illuminate\Testing\TestResponse;
use Lock\Server\Clients\ClientRepository;
use Lock\Server\Shared\Realms\IssuerResolver;
use Lock\Server\Tests\FeatureTestCase;
use Lock\Server\Tokens\Models\AccessToken;
use Lock\Server\Tokens\Pipeline\AccessTokenApi;
use Lock\Server\Tokens\Pipeline\AccessTokenPipeline;
use Lock\Server\Tokens\Pipeline\ClientCredentialsEvent;
use Symfony\Component\HttpFoundation\Response;

beforeEach(function (): void {
    $this->client = app(ClientRepository::class)->createClientCredentialsGrantClient('M2M');
});

/**
 * @param  array<string, mixed>  $extra
 * @return TestResponse<Response>
 */
function requestClientCredentials(FeatureTestCase $test, array $extra = []): TestResponse
{
    return $test->post('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $test->client->id,
        'client_secret' => $test->client->secret,
        'scope' => '',
        ...$extra,
    ]);
}

it('issues a userless token addressed to the realm audiences', function (): void {
    $accessToken = parseAccessToken((string) requestClientCredentials($this)->assertOk()->json('access_token'));

    expect($accessToken->claims()->get('aud'))->toBe([app(IssuerResolver::class)->url()])
        ->and($accessToken->claims()->get('client_id'))->toBe((string) $this->client->id)
        ->and($accessToken->claims()->get('sub'))->toBe((string) $this->client->id);
});

it('binds the token to an allowlisted resource and exposes it to the trigger', function (): void {
    $this->client->forceFill(['allowed_exchange_audiences' => ['https://mail.test']])->save();
    $seen = null;

    app(AccessTokenPipeline::class)->register('client_credentials', function (ClientCredentialsEvent $event) use (&$seen): void {
        $seen = $event->audiences;
    });

    $accessToken = parseAccessToken((string) requestClientCredentials($this, ['resource' => 'https://mail.test'])->assertOk()->json('access_token'));

    expect($accessToken->claims()->get('aud'))->toBe(['https://mail.test'])
        ->and($seen)->toBe(['https://mail.test']);
});

it('rejects a resource that is not allowlisted or not an absolute URI', function (string $resource): void {
    $this->client->forceFill(['allowed_exchange_audiences' => ['https://mail.test']])->save();

    requestClientCredentials($this, ['resource' => $resource])
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_target')
        ->assertJsonMissingPath('access_token');
})->with([
    'foreign resource' => 'https://somewhere-else.test',
    'relative resource' => 'not-a-uri',
]);

it('runs the client-credentials trigger once and applies its access-token claims', function (): void {
    $triggerCount = 0;

    app(AccessTokenPipeline::class)->register('client_credentials', function (ClientCredentialsEvent $event, AccessTokenApi $api) use (&$triggerCount): void {
        $triggerCount++;

        expect($event->client->key)->toBe((string) $this->client->id)
            ->and($event->scopes)->toBe([]);

        $api->setAccessTokenClaim('tenant', 'acme');
    });

    $accessToken = parseAccessToken((string) requestClientCredentials($this)->assertOk()->json('access_token'));

    expect($accessToken->claims()->get('tenant'))->toBe('acme')
        ->and($triggerCount)->toBe(1);
});

it('denies issuance before persisting when a trigger denies', function (): void {
    app(AccessTokenPipeline::class)->register('client_credentials', fn (ClientCredentialsEvent $event, AccessTokenApi $api) => $api->deny('client_blocked'));

    requestClientCredentials($this)
        ->assertStatus(400)
        ->assertJsonPath('error', 'access_denied')
        ->assertJsonMissingPath('access_token');

    expect(AccessToken::query()->count())->toBe(0);
});

it('grants the client default scopes when none are requested', function (): void {
    config(['oidc.scopes' => ['orders:read' => 'Read orders']]);
    $this->client->forceFill(['default_scopes' => ['orders:read']])->save();

    requestClientCredentials($this)->assertOk()->assertJsonPath('scope', 'orders:read');
});

it('rejects a known scope the client is not assigned with invalid_scope', function (): void {
    config(['oidc.scopes' => ['orders:read' => 'Read orders']]);
    $this->client->forceFill(['optional_scopes' => []])->save();

    requestClientCredentials($this, ['scope' => 'orders:read'])
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_scope');

    expect(AccessToken::query()->count())->toBe(0);
});

it('refuses a scope another resource owns and issues it once that resource is asked for', function (): void {
    config([
        'oidc.scopes' => ['orders:read' => 'Read orders'],
        'oidc.resources' => ['https://api.internal/orders' => ['scopes' => ['orders:read']]],
    ]);
    $this->client->forceFill(['allowed_exchange_audiences' => ['https://api.internal/orders']])->save();

    requestClientCredentials($this, ['scope' => 'orders:read'])
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_scope');

    requestClientCredentials($this, ['scope' => 'orders:read', 'resource' => 'https://api.internal/orders'])
        ->assertOk()
        ->assertJsonPath('scope', 'orders:read');
});
