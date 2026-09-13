<?php

declare(strict_types=1);

/**
 * OpenID Connect Core 1.0 §3.1.2.1 (acr_values)
 */

use Lock\Server\Authentication\Pipeline\LoginApi;
use Lock\Server\Authentication\Pipeline\LoginEvent;
use Lock\Server\Authentication\Pipeline\PostLoginPipeline;
use Lock\Server\Clients\ClientRepository;
use Lock\Server\Credentials\TotpFactorProvider;
use Workbench\App\Models\User;

beforeEach(function (): void {
    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'email_verified_at' => now(), 'password' => bcrypt('secret-password')]);
});

it('denies a login when the postLogin hook denies', function (): void {
    app(PostLoginPipeline::class)->register(fn (LoginEvent $e, LoginApi $api) => $api->deny('blocked'));

    $this->post(route('identity.login.store'), ['email' => 'm@example.com', 'password' => 'secret-password'])
        ->assertSessionHasErrors('email');

    $this->assertGuest('identity');
});

it('buffers postLogin id_token claims into the session', function (): void {
    app(PostLoginPipeline::class)->register(fn (LoginEvent $e, LoginApi $api) => $api->setIdTokenClaim('groups', ['admin']));

    $this->post(route('identity.login.store'), ['email' => 'm@example.com', 'password' => 'secret-password']);

    expect(session()->get('oidc.id_token_claims'))->toBe(['groups' => ['admin']]);
});

it('buffers postLogin access_token claims into the session', function (): void {
    app(PostLoginPipeline::class)->register(fn (LoginEvent $e, LoginApi $api) => $api->setAccessTokenClaim('tier', 'gold'));

    $this->post(route('identity.login.store'), ['email' => 'm@example.com', 'password' => 'secret-password']);

    expect(session()->get('oidc.access_token_claims'))->toBe(['tier' => 'gold']);
});

it('denies when requireMfa is requested and nothing can satisfy it', function (): void {
    config(['oidc.credentials.factors' => []]);
    app(PostLoginPipeline::class)->register(fn (LoginEvent $e, LoginApi $api) => $api->requireMfa());

    $this->post(route('identity.login.store'), ['email' => 'm@example.com', 'password' => 'secret-password'])
        ->assertSessionHasErrors('email');

    $this->assertGuest('identity');
});

it('forces the two-factor challenge when requireMfa is requested and a factor is enrolled', function (): void {
    $factor = app(TotpFactorProvider::class)->enroll($this->user);
    $factor->forceFill(['confirmed_at' => now()])->save();

    app(PostLoginPipeline::class)->register(fn (LoginEvent $e, LoginApi $api) => $api->requireMfa());

    $this->post(route('identity.login.store'), ['email' => 'm@example.com', 'password' => 'secret-password'])
        ->assertRedirect(route('identity.two-factor.login'))
        ->assertSessionHas('login.id', $this->user->getAuthIdentifier());

    $this->assertGuest('identity');
});

it('exposes the pending authorize request acr_values to postLogin hooks', function (): void {
    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/callback']);
    $captured = null;
    app(PostLoginPipeline::class)->register(function (LoginEvent $event) use (&$captured): void {
        $captured = $event;
    });

    $this->get('/oauth/authorize?'.http_build_query([
        'client_id' => $client->id,
        'redirect_uri' => 'https://rp.test/callback',
        'response_type' => 'code',
        'scope' => 'openid',
        'code_challenge' => str_repeat('c', 43),
        'code_challenge_method' => 'S256',
        'acr_values' => 'mfa phishing-resistant',
    ]))->assertRedirect();

    $this->post(route('identity.login.store'), ['email' => 'm@example.com', 'password' => 'secret-password']);

    expect($captured)->toBeInstanceOf(LoginEvent::class)
        ->and($captured->requestsAcr('mfa'))->toBeTrue()
        ->and($captured->requestsAcr('phr'))->toBeFalse()
        ->and($captured->requestedAcrValues)->toBe(['mfa', 'phishing-resistant'])
        ->and($captured->client?->clientId)->toBe((string) $client->id)
        ->and($captured->scopes)->toContain('openid');
});
