<?php

declare(strict_types=1);

use Illuminate\Auth\GenericUser;
use Lock\Server\Protocol\Ui\Pages\LogoutConfirmationPage;
use Lock\Server\Protocol\Ui\Views\LogoutPrompt;
use Lock\Server\Support\Testing\InteractsWithOidc;
use Workbench\App\Models\User;

uses(InteractsWithOidc::class);

function identityUser(): User
{
    return User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);
}

it('asks the signed-in user to confirm a GET logout that carries no verifiable hint', function (): void {
    $user = identityUser();
    $client = $this->createOidcClient('Test RP');
    $client->forceFill(['post_logout_redirect_uris' => ['https://rp.test/signed-out']])->save();

    $this->actingAsIdentity($user);

    $this->get(route('oidc.logout', ['client_id' => $client->id, 'post_logout_redirect_uri' => 'https://rp.test/signed-out', 'state' => 'st4te']), ['X-Inertia' => 'true'])
        ->assertOk()
        ->assertSee(__('oidc-ui::oauth.logout.requested-by', ['client' => 'Test RP']), false)
        ->assertSee('m@example.com', false)
        ->assertSee('logout_confirmation', false);

    expect(auth()->guard('identity')->check())->toBeTrue();
});

it('redirects a signed-out browser instead of rendering the prompt', function (): void {
    $this->get(route('oidc.logout'))
        ->assertRedirect(config('oidc.login.logout_redirect', '/'));
});

it('links cancel to the realm home and names no client when the request identified none', function (): void {
    $content = renderPage(new LogoutConfirmationPage(new LogoutPrompt(
        user: new GenericUser(['id' => 1]),
        client: null,
        postLogoutRedirectUri: null,
        state: null,
        confirmationToken: 'sealed',
    )));

    expect($content)->toContain(__('oidc-ui::oauth.logout.requested'))
        ->and($content)->not->toContain(__('oidc-ui::oauth.logout.signed-in-as', ['email' => 'null']))
        ->and($content)->toContain(config('oidc.login.home', '/dashboard'))
        ->and($content)->toContain('sealed');
});
