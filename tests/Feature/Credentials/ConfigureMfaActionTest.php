<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Hash;
use Illuminate\Testing\TestResponse;
use Lock\Server\Authentication\Pipeline\LoginApi;
use Lock\Server\Authentication\Pipeline\LoginEvent;
use Lock\Server\Authentication\Pipeline\PostLoginPipeline;
use Lock\Server\Credentials\TotpFactorProvider;
use Lock\Server\Shared\Authentication\PendingActions;
use Lock\Server\Support\Testing\FakesAuthViews;
use Symfony\Component\HttpFoundation\Response;
use Workbench\App\Models\User;

uses(FakesAuthViews::class);

beforeEach(function (): void {
    $this->fakeAuthViews();
});

function mfaUser(): User
{
    return User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('password')]);
}

function withConfirmedTotp(User $user): User
{
    app(TotpFactorProvider::class)->enroll($user)->forceFill(['confirmed_at' => now()])->save();

    return $user;
}

/**
 * @return TestResponse<Response>
 */
function passwordLogin(): TestResponse
{
    return test()->post(route('identity.login.store'), ['email' => 'm@example.com', 'password' => 'password']);
}

it('sends a user without a factor to enrollment when the realm always requires mfa', function (): void {
    config(['oidc.authentication.mfa' => 'always']);
    mfaUser();

    passwordLogin()->assertRedirect(route('identity.two-factor.setup'));

    $this->assertGuest('identity');
});

it('challenges instead of enrolling once a factor exists', function (): void {
    config(['oidc.authentication.mfa' => 'always']);
    withConfirmedTotp(mfaUser());

    passwordLogin()->assertRedirect(route('identity.two-factor.login'));
});

it('enrolls rather than denying when the pipeline demands mfa without a factor', function (): void {
    $user = mfaUser();
    app(PostLoginPipeline::class)->register(fn (LoginEvent $e, LoginApi $api) => $api->requireMfa());

    passwordLogin()->assertRedirect(route('identity.two-factor.setup'));

    $this->assertGuest('identity');
    expect(app(PendingActions::class)->for($user))->toBe(['configure_mfa']);
});

it('denies when the realm requires a factor that nothing can provide', function (): void {
    config(['oidc.authentication.mfa' => 'always', 'oidc.credentials.factors' => []]);
    mfaUser();

    passwordLogin()->assertSessionHasErrors('email');

    $this->assertGuest('identity');
});

it('denies a pipeline mfa demand in a realm with second factors switched off', function (): void {
    config(['oidc.authentication.mfa' => 'never']);
    withConfirmedTotp(mfaUser());
    app(PostLoginPipeline::class)->register(fn (LoginEvent $e, LoginApi $api) => $api->requireMfa());

    passwordLogin()->assertSessionHasErrors('email');
});

it('never challenges in a realm with second factors switched off', function (): void {
    config(['oidc.authentication.mfa' => 'never']);
    $user = withConfirmedTotp(mfaUser());

    passwordLogin()->assertRedirect(config('oidc.login.home'));

    $this->assertAuthenticatedAs($user, 'identity');
});

it('reaches the enrollment screen mid-login without a confirmed password', function (): void {
    config(['oidc.authentication.mfa' => 'always']);
    mfaUser();
    passwordLogin();

    $this->get(route('identity.two-factor.setup'))
        ->assertOk()
        ->assertJsonPath('prompt.required', true)
        ->assertJsonPath('prompt.enrolled', false);
});

it('continues the held login once a factor is confirmed', function (): void {
    config(['oidc.authentication.mfa' => 'always']);
    $user = mfaUser();
    passwordLogin();

    $this->post(route('identity.two-factor.setup.continue'))->assertStatus(409);

    withConfirmedTotp($user);

    $this->get(route('identity.two-factor.setup'))->assertJsonPath('prompt.enrolled', true);
    $this->post(route('identity.two-factor.setup.continue'))->assertRedirect(config('oidc.login.home'));

    $this->assertAuthenticatedAs($user->fresh(), 'identity');
});

it('still confirms a password before enrollment from a live session', function (): void {
    $user = mfaUser();
    $this->actingAs($user, 'identity');

    $this->get(route('identity.two-factor.setup'))->assertRedirect(route('identity.password.confirm'));
});
