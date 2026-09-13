<?php

declare(strict_types=1);

use Illuminate\Auth\GenericUser;
use Lock\Server\Clients\Models\Client;
use Lock\Server\Consents\Ui\Pages\OAuthConsentPage;
use Lock\Server\Shared\Consents\ConsentPrompt;
use Lock\Server\Shared\Scopes\Scope;
use Lock\Server\Support\Testing\InteractsWithOidc;
use Workbench\App\Models\User;

uses(InteractsWithOidc::class);

/**
 * @param  list<Scope>  $scopes
 */
function consentPrompt(Client $client, array $scopes): ConsentPrompt
{
    return new ConsentPrompt(
        client: $client->snapshot(),
        user: new GenericUser(['id' => 1]),
        scopes: $scopes,
        authToken: 'test-auth-token',
        resources: ['https://op.test'],
    );
}

it('serves this package\'s consent page for an authorization request', function (): void {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);
    $client = $this->createOidcClient('Test RP', ['https://rp.test/callback']);
    $pkce = $this->pkce();

    $this->actingAsIdentity($user)
        ->get(route('oidc.authorize', [
            'client_id' => $client->id,
            'redirect_uri' => 'https://rp.test/callback',
            'response_type' => 'code',
            'scope' => 'openid',
            'state' => 'st4te',
            'code_challenge' => $pkce->challenge,
            'code_challenge_method' => 'S256',
        ]), ['X-Inertia' => 'true'])
        ->assertOk()
        ->assertSee($client->name, false);
});

it('renders for a non-Eloquent user without leaking a null email into the translation', function (): void {
    $client = $this->createOidcClient('Test RP', ['https://rp.test/callback']);

    $content = renderPage(new OAuthConsentPage(consentPrompt($client, [new Scope('openid', 'OpenID Connect')])));

    expect($content)->toContain(__('oidc-ui::oauth.consent.signed-in-as', ['email' => '']))
        ->and($content)->not->toContain(__('oidc-ui::oauth.consent.signed-in-as', ['email' => 'null']));
});

it('lists only the visible scopes and drops the scopes heading when none are visible', function (): void {
    $client = $this->createOidcClient('Test RP', ['https://rp.test/callback']);
    $hidden = new Scope('internal:metrics', 'Internal metrics access', hidden: true);

    $mixed = renderPage(new OAuthConsentPage(consentPrompt($client, [new Scope('openid', 'OpenID Connect'), $hidden])));
    $hiddenOnly = renderPage(new OAuthConsentPage(consentPrompt($client, [$hidden])));

    expect($mixed)->toContain(__('oidc-ui::oauth.consent.requested-scopes'))
        ->and($mixed)->toContain('OpenID Connect')
        ->and($mixed)->not->toContain('Internal metrics access')
        ->and($hiddenOnly)->not->toContain(__('oidc-ui::oauth.consent.requested-scopes'));
});
