<?php

declare(strict_types=1);

use Illuminate\Http\Client\Request as ClientRequest;
use Illuminate\Support\Facades\Context;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use Lock\Server\Clients\ClientRepository;
use Lock\Server\Realms\Http\Middleware\ResolveRealm;
use Lock\Server\Sessions\OidcSessionRepository;
use Lock\Server\Shared\Context\OidcContext;
use Lock\Server\Shared\Http\DnsResolver;
use Lock\Server\Support\Testing\InteractsWithOidc;
use Lock\Server\Tests\Support\Realms\RecordResolvedRealm;
use Lock\Server\Tests\Support\Realms\RoutesRealmsByPath;
use Workbench\App\Models\User;

uses(RoutesRealmsByPath::class, InteractsWithOidc::class);

beforeEach(function (): void {
    fakeConsentViewUsing(fn (array $parameters) => response()->json(['authToken' => $parameters['authToken']]));

    config([
        'oidc.realm' => 'default',
        'oidc.issuer' => 'https://id.example.com',
        'queue.default' => 'database',
    ]);

    RecordResolvedRealm::forget();

    Route::middleware(ResolveRealm::class)
        ->prefix('realms/{realm}')
        ->where(['realm' => '[A-Za-z0-9._-]+'])
        ->get('test/queue', function (): string {
            RecordResolvedRealm::dispatch();

            return 'queued';
        });
});

it('publishes the realm a request resolved to', function (): void {
    $this->get('/realms/acme/.well-known/openid-configuration')->assertOk();

    expect(Context::get(OidcContext::REALM))->toBe('acme');
});

it('publishes the client an authorize request names, and the one that authenticates at the token endpoint', function (): void {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => bcrypt('secret')]);
    $client = $this->createOidcClient();

    $this->authorizeAndApprove($user, $client)->response->assertOk();

    expect(Context::get(OidcContext::CLIENT))->toBe($client->client_id);
});

it('records the client even when the authorize request is rejected afterwards', function (): void {
    $client = $this->createOidcClient();

    $this->get(route('oidc.authorize', ['client_id' => $client->client_id, 'redirect_uri' => 'https://attacker.test/cb']))
        ->assertStatus(400);

    expect(Context::get(OidcContext::CLIENT))->toBe($client->client_id);
});

it('resolves the realm a job was dispatched from, not the configured one', function (): void {
    $this->get('/realms/acme/test/queue')->assertOk();

    forgetRequest();
    workQueue();

    expect(RecordResolvedRealm::$seen['realm'])->toBe('acme')
        ->and(RecordResolvedRealm::$seen['issuer'])->toBe('https://id.example.com/realms/acme');
});

// The realm has to be the URL default before the job body runs, or a queued
// password-reset notification links the user into the wrong realm.
it('generates realm urls inside a queued job', function (): void {
    $this->get('/realms/acme/test/queue')->assertOk();

    forgetRequest();
    workQueue();

    expect(RecordResolvedRealm::$seen['authorize_path'])->toBe('/realms/acme/oauth/authorize');
});

it('falls back to the configured realm for a job dispatched outside a request', function (): void {
    RecordResolvedRealm::dispatch();

    forgetRequest();
    workQueue();

    expect(RecordResolvedRealm::$seen['realm'])->toBe('default')
        ->and(RecordResolvedRealm::$seen['authorize_path'])->toBe('/realms/default/oauth/authorize');
});

it('carries the client of the request that queued the job', function (): void {
    $client = $this->createOidcClient();

    $this->get(route('oidc.authorize', ['client_id' => $client->client_id, 'redirect_uri' => 'https://attacker.test/cb']))
        ->assertStatus(400);

    RecordResolvedRealm::dispatch();

    forgetRequest();
    workQueue();

    expect(RecordResolvedRealm::$seen['client'])->toBe($client->client_id);
});

it('sends a back-channel logout for the realm the job was dispatched from', function (): void {
    $this->mock(DnsResolver::class)->shouldReceive('addresses')->once()->with('rp.test')->andReturn(['1.1.1.1']);
    Http::fake();

    $this->get('/realms/acme/.well-known/openid-configuration')->assertOk();
    generateRealmSigningKey();

    $sid = app(OidcSessionRepository::class)->start((string) User::factory()->create()->getKey());
    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/cb']);
    $client->forceFill(['backchannel_logout_uri' => 'https://rp.test/bclo'])->save();

    app(OidcSessionRepository::class)->recordParticipant($sid, (string) $client->getKey());
    app(OidcSessionRepository::class)->revoke($sid);

    forgetRequest();
    workQueue();

    Http::assertSent(fn (ClientRequest $request): bool => $request->url() === 'https://rp.test/bclo'
        && parseAccessToken((string) $request['logout_token'])->claims()->get('iss') === 'https://id.example.com/realms/acme');
});
