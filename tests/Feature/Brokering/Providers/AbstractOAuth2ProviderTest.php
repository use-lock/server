<?php

declare(strict_types=1);

/**
 * Upstream OAuth 2.0 client leg: RFC 7636 S256 PKCE, state binding (RFC 6749 §10.12), code exchange
 */

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Lock\Server\Brokering\PendingSocialRedirect;
use Lock\Server\Brokering\Providers\AbstractOAuth2Provider;
use Lock\Server\Brokering\TokenResponse;
use Lock\Server\Shared\Brokering\InvalidStateException;
use Lock\Server\Shared\Brokering\SocialUser;

/**
 * @param  array<string, mixed>  $config
 */
function fakeOAuth2Provider(array $config = []): AbstractOAuth2Provider
{
    return new class('fake', $config + ['client_id' => 'client-1', 'client_secret' => 'shhh']) extends AbstractOAuth2Provider
    {
        protected function authorizationEndpoint(): string
        {
            return 'https://provider.test/authorize';
        }

        protected function tokenEndpoint(): string
        {
            return 'https://provider.test/token';
        }

        protected function defaultScopes(): array
        {
            return ['profile'];
        }

        protected function fetchUser(TokenResponse $tokens, PendingSocialRedirect $pending, Request $request): SocialUser
        {
            return new SocialUser(
                id: 'fake-1',
                email: null,
                emailVerified: false,
                name: null,
                nickname: null,
                avatar: null,
                accessToken: $tokens->accessToken,
            );
        }
    };
}

/**
 * @param  array<string, mixed>  $query
 */
function requestWithSession(string $uri = '/auth/social/fake/callback', array $query = []): Request
{
    $request = Request::create($uri, 'GET', $query);
    $request->setLaravelSession(app('session.store'));

    return $request;
}

it('redirects to the authorization endpoint with state and S256 PKCE', function (): void {
    $request = requestWithSession('/auth/social/fake');

    $response = fakeOAuth2Provider()->redirect($request);

    parse_str((string) parse_url($response->headers->get('Location'), PHP_URL_QUERY), $params);
    $pending = PendingSocialRedirect::pull($request);

    expect($response->headers->get('Location'))->toStartWith('https://provider.test/authorize?')
        ->and($params['client_id'])->toBe('client-1')
        ->and($params['response_type'])->toBe('code')
        ->and($params['scope'])->toBe('profile')
        ->and($params['state'])->toBe($pending->state)
        ->and($params['code_challenge_method'])->toBe('S256')
        ->and($params['code_challenge'])->toBe(
            rtrim(strtr(base64_encode(hash('sha256', $pending->codeVerifier, true)), '+/', '-_'), '=')
        )
        ->and($params['redirect_uri'])->toBe(route('identity.social.callback', ['provider' => 'fake']));
});

it('exchanges the callback code including the PKCE verifier', function (): void {
    Http::fake(['https://provider.test/token' => Http::response(['access_token' => 'at-1', 'token_type' => 'Bearer'])]);

    $pending = new PendingSocialRedirect('fake', 'login', 'state-1', 'verifier-1', null);
    $request = requestWithSession(query: ['code' => 'code-1', 'state' => 'state-1']);

    $user = fakeOAuth2Provider()->user($request, $pending);

    expect($user->accessToken)->toBe('at-1');
    Http::assertSent(fn ($httpRequest): bool => $httpRequest->url() === 'https://provider.test/token'
        && $httpRequest['code'] === 'code-1'
        && $httpRequest['code_verifier'] === 'verifier-1'
        && $httpRequest['client_secret'] === 'shhh'
        && $httpRequest['grant_type'] === 'authorization_code');
});

it('rejects a state mismatch', function (): void {
    $pending = new PendingSocialRedirect('fake', 'login', 'state-1', null, null);
    $request = requestWithSession(query: ['code' => 'code-1', 'state' => 'tampered']);

    fakeOAuth2Provider()->user($request, $pending);
})->throws(InvalidStateException::class);

it('rejects a pending authorization for a different provider', function (): void {
    $pending = new PendingSocialRedirect('other', 'login', 'state-1', null, null);
    $request = requestWithSession(query: ['code' => 'code-1', 'state' => 'state-1']);

    fakeOAuth2Provider()->user($request, $pending);
})->throws(InvalidStateException::class);
