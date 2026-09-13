<?php

declare(strict_types=1);

use Illuminate\Contracts\Auth\CanResetPassword;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Lock\Server\Clients\ClientRepository;
use Lock\Server\Credentials\Models\PasswordHistory;
use Lock\Server\Support\Testing\FakesAuthViews;
use Lock\Server\Support\Testing\InteractsWithOidc;
use Lock\Server\Support\Testing\PkcePair;
use Workbench\App\Models\User;

uses(FakesAuthViews::class, InteractsWithOidc::class);

/**
 * A session established before the realm's rules caught up with it — the
 * password aged out, or the realm turned a requirement on. The authorization
 * endpoint is the only place left to notice.
 */
function sessionWithExpiredPassword(): User
{
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('password')]);

    $user->hasMany(PasswordHistory::class, 'user_id')
        ->create(['hash' => $user->getAuthPassword(), 'created_at' => now()->subDays(90)]);

    test()->actingAs($user, 'identity');

    return $user;
}

/**
 * @param  array<string, mixed>  $extra
 */
function authorizeQuery(string $clientId, string $redirectUri, array $extra = []): string
{
    $pkce = PkcePair::generate();

    return route('oidc.authorize').'?'.http_build_query(array_merge([
        'client_id' => $clientId,
        'redirect_uri' => $redirectUri,
        'response_type' => 'code',
        'scope' => 'openid',
        'state' => Str::random(16),
        'code_challenge' => $pkce->challenge,
        'code_challenge_method' => 'S256',
    ], $extra));
}

it('refuses an authorization code while an action is open on a live session', function (): void {
    config(['oidc.password_policy.max_age_days' => 30]);
    $this->fakeAuthViews();
    sessionWithExpiredPassword();
    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/callback']);

    $this->get(authorizeQuery($client->client_id, 'https://rp.test/callback'))
        ->assertRedirect(route('identity.password.change'));
});

it('reports interaction_required rather than prompting when the client forbade it', function (): void {
    config(['oidc.password_policy.max_age_days' => 30]);
    sessionWithExpiredPassword();
    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/callback']);

    $response = $this->get(authorizeQuery($client->client_id, 'https://rp.test/callback', ['prompt' => 'none']));

    $response->assertRedirect();
    expect($response->headers->get('Location'))->toContain('error=interaction_required');
});

it('returns to the authorization request once the action is settled', function (): void {
    config(['oidc.password_policy.max_age_days' => 30]);
    $this->fakeAuthViews();
    resetUserPasswordsUsing(function (CanResetPassword $user, array $input): void {
        $user->forceFill(['password' => Hash::make($input['password'])]);
    });
    sessionWithExpiredPassword();
    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/callback']);
    $authorizeUrl = authorizeQuery($client->client_id, 'https://rp.test/callback');

    $this->get($authorizeUrl)->assertRedirect(route('identity.password.change'));

    $response = $this->post(route('identity.password.change.store'), [
        'current_password' => 'password',
        'password' => 'a-brand-new-password',
        'password_confirmation' => 'a-brand-new-password',
    ]);

    // fullUrl() sorts the query, so the request comes back reordered but intact.
    parse_str((string) parse_url((string) $response->headers->get('Location'), PHP_URL_QUERY), $returned);
    parse_str((string) parse_url($authorizeUrl, PHP_URL_QUERY), $sent);

    expect($response->headers->get('Location'))->toStartWith(route('oidc.authorize'))
        ->and($returned)->toEqual($sent);
});

it('issues a code as usual when nothing is open', function (): void {
    config(['oidc.password_policy.max_age_days' => 30]);
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('password')]);
    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/callback']);

    fakeConsentViewUsing(fn (array $parameters) => response()->json(['authToken' => $parameters['authToken']]));

    $result = $this->authorizeAndApprove($user, $client);

    expect($result->accessToken)->not->toBeEmpty()
        ->and($result->idToken)->not->toBeEmpty();
});
