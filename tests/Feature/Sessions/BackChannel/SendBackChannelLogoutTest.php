<?php

declare(strict_types=1);

use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Request;
use Illuminate\Http\Client\RequestException;
use Illuminate\Support\Facades\Bus;
use Illuminate\Support\Facades\Http;
use Lcobucci\JWT\Token\Plain;
use Lock\Server\Clients\Models\Client;
use Lock\Server\Sessions\BackChannel\SendBackChannelLogout;
use Lock\Server\Sessions\Models\OidcSession;
use Lock\Server\Sessions\Models\SessionParticipant;
use Lock\Server\Sessions\OidcSessionRepository;
use Lock\Server\Shared\Context\OidcContext;
use Lock\Server\Shared\Http\DnsResolver;
use Lock\Server\Shared\Realms\CurrentRealm;
use Lock\Server\Shared\Realms\RealmResolver;
use Lock\Server\Shared\SigningKeys\Keyring;

it('posts a logout token once and records its successful delivery', function (): void {
    $this->mock(DnsResolver::class)->shouldReceive('addresses')->once()->with('rp.test')->andReturn(['1.1.1.1']);
    Http::fake();
    $session = OidcSession::factory()->revoked()->create();
    $client = Client::factory()->create(['backchannel_logout_uri' => 'https://rp.test/bclo']);
    $participant = SessionParticipant::factory()->inSession($session)->forClient($client)->create();

    SendBackChannelLogout::dispatchSync($participant->id, $session->realm);
    SendBackChannelLogout::dispatchSync($participant->id, $session->realm);

    Http::assertSentCount(1);
    Http::assertSent(fn (Request $request): bool => $request->url() === 'https://rp.test/bclo'
        && is_string($request['logout_token'])
        && $request['logout_token'] !== '');
    expect($participant->refresh()->logout_status)->toBe('delivered')
        ->and($session->refresh()->logout_finished_at)->not->toBeNull();
});

it('sends nothing when the session, the client or its logout URI is missing', function (string $case): void {
    Http::fake();
    $session = OidcSession::factory()->revoked()->create();
    $client = Client::factory()->create(['backchannel_logout_uri' => 'https://rp.test/bclo']);
    $participant = SessionParticipant::factory()->inSession($session)->forClient($client)->create();

    match ($case) {
        'missing session' => $session->delete(),
        'missing client' => $client->delete(),
        'no logout URI' => $client->update(['backchannel_logout_uri' => null]),
        default => throw new LogicException('Unknown case.'),
    };

    SendBackChannelLogout::dispatchSync($participant->id, $session->realm);

    Http::assertNothingSent();

    if ($case === 'no logout URI') {
        expect($participant->refresh()->logout_status)->toBe('skipped');
    }
})->with(['missing session', 'missing client', 'no logout URI']);

it('keeps unsuccessful delivery pending for retry', function (int $status): void {
    $this->mock(DnsResolver::class)->shouldReceive('addresses')->once()->with('rp.test')->andReturn(['1.1.1.1']);
    Http::fake(['*' => Http::response('', $status)]);
    $session = OidcSession::factory()->revoked()->create();
    $participant = SessionParticipant::factory()->inSession($session)
        ->forClient(Client::factory()->create(['backchannel_logout_uri' => 'https://rp.test/bclo']))->create();

    expect(fn () => SendBackChannelLogout::dispatchSync($participant->id, $session->realm))->toThrow(RequestException::class);
    expect($participant->refresh()->logout_status)->toBeNull()
        ->and($session->refresh()->logout_finished_at)->toBeNull();
})->with([302, 503]);

it('signs for the recorded realm and restores the worker context', function (): void {
    $this->mock(DnsResolver::class)->shouldReceive('addresses')->once()->with('rp.test')->andReturn(['1.1.1.1']);
    Http::fake();
    config(['oidc.issuer' => 'https://id.test', 'oidc.routes.realms' => 'path']);
    [$session, $participant] = CurrentRealm::runAs('acme', function (): array {
        generateRealmSigningKey();
        $session = OidcSession::factory()->revoked()->create();
        $participant = SessionParticipant::factory()->inSession($session)
            ->forClient(Client::factory()->create(['client_id' => 'acme-rp', 'backchannel_logout_uri' => 'https://rp.test/bclo']))->create();

        return [$session, $participant];
    });

    CurrentRealm::runAs('globex', function () use ($session, $participant): void {
        SendBackChannelLogout::dispatchSync($participant->id, $session->realm);

        expect(app(RealmResolver::class)->current()->identifier())->toBe('globex')
            ->and(OidcContext::realm())->toBe('globex');
    });

    Http::assertSent(function (Request $request): bool {
        $token = parseIdToken($request['logout_token']);

        return $token instanceof Plain
            && $token->claims()->get('iss') === 'https://id.test/realms/acme'
            && $token->claims()->get('aud') === ['acme-rp']
            && CurrentRealm::runAs('acme', fn (): bool => app(Keyring::class)->verifies($token));
    });
});

it('fails logout delivery without a request when DNS includes a non-public address', function (array $addresses): void {
    $this->mock(DnsResolver::class)->shouldReceive('addresses')->once()->with('rp.test')->andReturn($addresses);
    Http::fake(['https://rp.test/bclo' => Http::response()]);
    $session = OidcSession::factory()->revoked()->create();
    $participant = SessionParticipant::factory()->inSession($session)
        ->forClient(Client::factory()->create(['backchannel_logout_uri' => 'https://rp.test/bclo']))->create();

    SendBackChannelLogout::dispatchSync($participant->id, $session->realm);
    SendBackChannelLogout::dispatchSync($participant->id, $session->realm);

    Http::assertNothingSent();
    expect($participant->refresh()->logout_status)->toBe('failed')
        ->and($session->refresh()->logout_finished_at)->not->toBeNull();
})->with([
    'private IPv4' => [['10.0.0.1']],
    'private IPv6' => [['fd00::1']],
    'mixed public and private' => [['1.1.1.1', '127.0.0.1']],
    'mixed IPv4 and IPv6' => [['1.1.1.1', '::1']],
    'IPv4 mapped' => [['::ffff:127.0.0.1']],
    'metadata service' => [['169.254.169.254']],
    'carrier NAT' => [['100.64.0.1']],
    'multicast' => [['224.0.0.1']],
    'NAT64' => [['64:ff9b::7f00:1']],
]);

it('pins logout delivery to the checked address with TLS verification and no proxy', function (string $address, string $resolved): void {
    $this->mock(DnsResolver::class)->shouldReceive('addresses')->once()->with('rp.test')->andReturn([$address]);
    $options = [];
    Http::fake(['https://rp.test:8443/bclo' => function (Request $request, array $requestOptions) use (&$options) {
        $options = $requestOptions;

        return Http::response();
    }]);
    $session = OidcSession::factory()->revoked()->create();
    $participant = SessionParticipant::factory()->inSession($session)
        ->forClient(Client::factory()->create(['backchannel_logout_uri' => 'https://rp.test:8443/bclo']))->create();

    SendBackChannelLogout::dispatchSync($participant->id, $session->realm);

    Http::assertSentCount(1);
    expect($options)->toMatchArray(['proxy' => '', 'verify' => true, 'allow_redirects' => false])
        ->and($options['curl'][CURLOPT_RESOLVE])->toBe([$resolved])
        ->and($participant->refresh()->logout_status)->toBe('delivered');
})->with([
    'IPv4' => ['1.1.1.1', 'rp.test:8443:1.1.1.1'],
    'IPv6' => ['2606:4700:4700::1111', 'rp.test:8443:[2606:4700:4700::1111]'],
]);

it('rechecks DNS before retrying a logout delivery', function (): void {
    $this->mock(DnsResolver::class)->shouldReceive('addresses')->twice()->with('rp.test')
        ->andReturn(['1.1.1.1'], ['127.0.0.1']);
    Http::fake(['https://rp.test/bclo' => Http::response('', 503)]);
    $session = OidcSession::factory()->revoked()->create();
    $participant = SessionParticipant::factory()->inSession($session)
        ->forClient(Client::factory()->create(['backchannel_logout_uri' => 'https://rp.test/bclo']))->create();

    expect(fn () => SendBackChannelLogout::dispatchSync($participant->id, $session->realm))->toThrow(RequestException::class);
    SendBackChannelLogout::dispatchSync($participant->id, $session->realm);

    Http::assertSentCount(1);
    expect($participant->refresh()->logout_status)->toBe('failed');
});

it('leaves unresolved logout destinations pending for retry without sending a request', function (): void {
    $this->mock(DnsResolver::class)->shouldReceive('addresses')->once()->with('rp.test')->andReturn([]);
    Http::fake(['https://rp.test/bclo' => Http::response()]);
    $session = OidcSession::factory()->revoked()->create();
    $participant = SessionParticipant::factory()->inSession($session)
        ->forClient(Client::factory()->create(['backchannel_logout_uri' => 'https://rp.test/bclo']))->create();

    expect(fn () => SendBackChannelLogout::dispatchSync($participant->id, $session->realm))->toThrow(ConnectionException::class);

    Http::assertNothingSent();
    expect($participant->refresh()->logout_status)->toBeNull();
});

it('rejects unsafe stored logout URLs even when registration was bypassed', function (): void {
    Http::fake();
    $session = OidcSession::factory()->revoked()->create();
    $participant = SessionParticipant::factory()->inSession($session)
        ->forClient(Client::factory()->create(['backchannel_logout_uri' => 'https://127.0.0.1/bclo']))->create();

    SendBackChannelLogout::dispatchSync($participant->id, $session->realm);

    Http::assertNothingSent();
    expect($participant->refresh()->logout_status)->toBe('failed');
});

it('delivers a queued logout after its session was deleted only within the retry lifetime', function (bool $expired): void {
    Bus::fake([SendBackChannelLogout::class]);
    $this->mock(DnsResolver::class)->shouldReceive('addresses')->times($expired ? 0 : 1)->with('rp.test')->andReturn(['1.1.1.1']);
    Http::fake();
    $session = OidcSession::factory()->create();
    $client = Client::factory()->create(['backchannel_logout_uri' => 'https://rp.test/bclo']);
    SessionParticipant::factory()->inSession($session)->forClient($client)->create();

    app(OidcSessionRepository::class)->revoke($session->id);
    $job = Bus::dispatched(SendBackChannelLogout::class)->sole();
    $session->delete();

    if ($expired) {
        $this->travel(2)->days();
    }

    app()->call([unserialize(serialize($job)), 'handle']);

    Http::assertSentCount($expired ? 0 : 1);

    if ($expired) {
        return;
    }

    Http::assertSent(function (Request $request) use ($session, $client): bool {
        $token = parseIdToken($request['logout_token']);

        return $token instanceof Plain
            && $token->claims()->get('sid') === $session->id
            && $token->claims()->get('sub') === $session->user_id
            && $token->claims()->get('aud') === [$client->client_id];
    });
})->with([false, true]);
