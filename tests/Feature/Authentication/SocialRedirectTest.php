<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Http;
use Lock\Server\Brokering\PendingSocialRedirect;

function enableCorpProvider(): void
{
    config()->set('oidc.social.providers.corp', [
        'driver' => 'oidc',
        'issuer' => 'https://idp.test',
        'client_id' => 'client-1',
        'client_secret' => 'shhh',
    ]);

    Http::fake([
        'https://idp.test/.well-known/openid-configuration' => Http::response([
            'issuer' => 'https://idp.test',
            'authorization_endpoint' => 'https://idp.test/authorize',
            'token_endpoint' => 'https://idp.test/token',
            'jwks_uri' => 'https://idp.test/jwks',
        ]),
    ]);
}

it('redirects to the upstream provider and stores the pending authorization', function (): void {
    enableCorpProvider();

    $response = $this->get(route('identity.social.redirect', ['provider' => 'corp']));

    $response->assertRedirect();
    expect($response->headers->get('Location'))->toStartWith('https://idp.test/authorize?')
        ->and(session(PendingSocialRedirect::SESSION_KEY)['provider'])->toBe('corp')
        ->and(session(PendingSocialRedirect::SESSION_KEY)['intent'])->toBe('login');
});

it('responds 404 for an unknown or credential-less provider', function (): void {
    $this->get(route('identity.social.redirect', ['provider' => 'github']))->assertNotFound();
    $this->get(route('identity.social.redirect', ['provider' => 'nope']))->assertNotFound();
});

it('bounces the form_post callback to a GET so the session cookie is available', function (): void {
    enableCorpProvider();

    $this->post(route('identity.social.callback', ['provider' => 'corp']), [
        'code' => 'code-1',
        'state' => 'state-1',
        'user' => '{"name":{"firstName":"Mona"}}',
    ])->assertStatus(303)->assertRedirect(
        route('identity.social.callback', ['provider' => 'corp'])
            .'?'.http_build_query(['code' => 'code-1', 'state' => 'state-1', 'user' => '{"name":{"firstName":"Mona"}}']),
    );
});

it('redirects to login with an error when the provider reports one', function (): void {
    enableCorpProvider();

    $this->get(route('identity.social.callback', ['provider' => 'corp']).'?error=access_denied')
        ->assertRedirect(route('identity.login'))
        ->assertSessionHasErrors('social');
});

it('redirects to login when no pending authorization exists', function (): void {
    enableCorpProvider();

    $this->get(route('identity.social.callback', ['provider' => 'corp']).'?code=x&state=y')
        ->assertRedirect(route('identity.login'))
        ->assertSessionHasErrors('social');
});

it('uses an external Inertia location for social login', function (): void {
    enableCorpProvider();

    $response = $this->get(route('identity.social.redirect', ['provider' => 'corp']), ['X-Inertia' => 'true'])
        ->assertStatus(409);

    expect($response->headers->get('X-Inertia-Location'))->toStartWith('https://idp.test/authorize?')
        ->and(session(PendingSocialRedirect::SESSION_KEY)['intent'])->toBe('login');
});
