<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Lock\Server\Brokering\PendingSocialRedirect;
use Lock\Server\Brokering\Providers\GitHubProvider;
use Lock\Server\Shared\Brokering\SocialAuthenticationException;

function githubProvider(): GitHubProvider
{
    return new GitHubProvider('github', ['client_id' => 'client-1', 'client_secret' => 'shhh']);
}

function githubCallback(): Request
{
    $request = Request::create('/auth/social/github/callback', 'GET', ['code' => 'code-1', 'state' => 'state-1']);
    $request->setLaravelSession(app('session.store'));

    return $request;
}

it('redirects to GitHub without PKCE and with default scopes', function (): void {
    $request = Request::create('/auth/social/github');
    $request->setLaravelSession(app('session.store'));

    $response = githubProvider()->redirect($request);
    parse_str((string) parse_url($response->headers->get('Location'), PHP_URL_QUERY), $params);

    expect($response->headers->get('Location'))->toStartWith('https://github.com/login/oauth/authorize?')
        ->and($params['scope'])->toBe('read:user user:email')
        ->and($params)->not->toHaveKey('code_challenge');
});

it('builds the user from the profile and the verified primary email', function (): void {
    Http::fake([
        'https://github.com/login/oauth/access_token' => Http::response(['access_token' => 'gh-at', 'token_type' => 'bearer']),
        'https://api.github.com/user' => Http::response([
            'id' => 12345,
            'login' => 'mona',
            'name' => 'Mona Lisa',
            'avatar_url' => 'https://avatars.github.test/mona',
            'email' => null,
        ]),
        'https://api.github.com/user/emails' => Http::response([
            ['email' => 'unverified@example.com', 'primary' => false, 'verified' => false],
            ['email' => 'mona@example.com', 'primary' => true, 'verified' => true],
        ]),
    ]);

    $pending = new PendingSocialRedirect('github', 'login', 'state-1', null, null);
    $user = githubProvider()->user(githubCallback(), $pending);

    expect($user->id)->toBe('12345')
        ->and($user->nickname)->toBe('mona')
        ->and($user->name)->toBe('Mona Lisa')
        ->and($user->email)->toBe('mona@example.com')
        ->and($user->emailVerified)->toBeTrue()
        ->and($user->avatar)->toBe('https://avatars.github.test/mona');
});

it('wraps profile fetch failures in a social authentication exception', function (): void {
    Http::fake([
        'https://github.com/login/oauth/access_token' => Http::response(['access_token' => 'gh-at', 'token_type' => 'bearer']),
        'https://api.github.com/user' => Http::response([], 500),
    ]);

    $pending = new PendingSocialRedirect('github', 'login', 'state-1', null, null);

    githubProvider()->user(githubCallback(), $pending);
})->throws(SocialAuthenticationException::class);

it('reports no verified email when GitHub has none', function (): void {
    Http::fake([
        'https://github.com/login/oauth/access_token' => Http::response(['access_token' => 'gh-at', 'token_type' => 'bearer']),
        'https://api.github.com/user' => Http::response(['id' => 12345, 'login' => 'mona', 'name' => null, 'avatar_url' => null, 'email' => null]),
        'https://api.github.com/user/emails' => Http::response([
            ['email' => 'unverified@example.com', 'primary' => true, 'verified' => false],
        ]),
    ]);

    $pending = new PendingSocialRedirect('github', 'login', 'state-1', null, null);
    $user = githubProvider()->user(githubCallback(), $pending);

    expect($user->email)->toBeNull()->and($user->emailVerified)->toBeFalse();
});
