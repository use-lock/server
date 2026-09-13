<?php

declare(strict_types=1);

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\URL;
use Illuminate\Testing\TestResponse;
use Lock\Server\Authentication\Contracts\RequiredAction;
use Lock\Server\Authentication\Events\RequiredActionCompleted;
use Lock\Server\Authentication\Pipeline\LoginApi;
use Lock\Server\Authentication\Pipeline\LoginEvent;
use Lock\Server\Authentication\Pipeline\PostLoginPipeline;
use Lock\Server\Authentication\RequiredActions\PendingRequiredActions;
use Lock\Server\Authentication\RequiredActions\RequiredActionRegistry;
use Lock\Server\Shared\Authentication\LoginDestination;
use Lock\Server\Shared\Authentication\PendingActions;
use Lock\Server\Shared\Realms\Realm;
use Lock\Server\Support\Testing\FakesAuthViews;
use Symfony\Component\HttpFoundation\Response;
use Workbench\App\Models\User;

uses(FakesAuthViews::class);

beforeEach(function (): void {
    $this->fakeAuthViews();
});

function unverifiedUser(string $email = 'm@example.com'): User
{
    return User::create(['name' => 'M', 'email' => $email, 'password' => Hash::make('password')]);
}

function verificationUrl(User $user): string
{
    return URL::temporarySignedRoute('identity.verification.verify', now()->addHour(), [
        'id' => $user->getKey(),
        'hash' => sha1($user->getEmailForVerification()),
    ]);
}

/**
 * @return TestResponse<Response>
 */
function logIn(string $email = 'm@example.com'): TestResponse
{
    return test()->post(route('identity.login.store'), ['email' => $email, 'password' => 'password']);
}

it('holds the login on the verify-email screen when the realm requires it', function (): void {
    config(['oidc.authentication.email_verification_required' => true]);
    unverifiedUser();

    logIn()->assertRedirect(route('identity.verification.notice'));

    $this->assertGuest('identity');
    expect(PendingRequiredActions::find())->not->toBeNull();
});

it('lets a verified user straight through', function (): void {
    config(['oidc.authentication.email_verification_required' => true]);
    $user = unverifiedUser();
    $user->forceFill(['email_verified_at' => now()])->save();

    logIn()->assertRedirect(config('oidc.login.home'));

    $this->assertAuthenticatedAs($user, 'identity');
});

it('does not require verification when the realm does not ask for it', function (): void {
    config(['oidc.authentication.email_verification_required' => false]);
    $user = unverifiedUser();

    logIn()->assertRedirect(config('oidc.login.home'));

    $this->assertAuthenticatedAs($user, 'identity');
});

it('reports the open actions to a json client instead of redirecting', function (): void {
    config(['oidc.authentication.email_verification_required' => true]);
    unverifiedUser();

    $this->postJson(route('identity.login.store'), ['email' => 'm@example.com', 'password' => 'password'])
        ->assertOk()
        ->assertJsonPath('required_actions', ['verify_email']);
});

it('reaches the verify-email screen and its resend without a session', function (): void {
    config(['oidc.authentication.email_verification_required' => true]);
    Notification::fake();
    unverifiedUser();
    logIn();

    $this->get(route('identity.verification.notice'))->assertOk();
    $this->post(route('identity.verification.send'))->assertRedirect();

    $this->assertGuest('identity');
});

it('sends the user to login when no session and no pending login name a subject', function (): void {
    $this->get(route('identity.verification.notice'))->assertRedirect(app(LoginDestination::class)->url());
});

it('completes the login once the signed link confirms the address', function (): void {
    config(['oidc.authentication.email_verification_required' => true]);
    $user = unverifiedUser();
    logIn();

    $this->get(verificationUrl($user))->assertRedirect(config('oidc.login.home').'?verified=1');

    $this->assertAuthenticatedAs($user->fresh(), 'identity');
    expect($user->fresh()->hasVerifiedEmail())->toBeTrue()
        ->and(PendingRequiredActions::find())->toBeNull();
});

it('refuses a link that names a different user', function (): void {
    config(['oidc.authentication.email_verification_required' => true]);
    unverifiedUser();
    $other = unverifiedUser('other@example.com');
    logIn();

    $this->get(verificationUrl($other))->assertForbidden();

    $this->assertGuest('identity');
});

it('runs the post-login pipeline before the actions, so a denial still wins', function (): void {
    config(['oidc.authentication.email_verification_required' => true]);
    unverifiedUser();
    app(PostLoginPipeline::class)->register(fn (LoginEvent $e, LoginApi $api) => $api->deny('blocked'));

    logIn()->assertSessionHasErrors('email');

    expect(PendingRequiredActions::find())->toBeNull();
});

it('lets the pipeline require a registered action for this login only', function (): void {
    $user = unverifiedUser();
    app(PostLoginPipeline::class)->register(fn (LoginEvent $e, LoginApi $api) => $api->requireAction('verify_email'));

    logIn()->assertRedirect(route('identity.verification.notice'));

    $this->assertGuest('identity');
    expect(app(PendingActions::class)->for($user))->toBe(['verify_email']);
});

it('drops an action nobody registered rather than stranding the login', function (): void {
    $user = unverifiedUser();
    app(PostLoginPipeline::class)->register(fn (LoginEvent $e, LoginApi $api) => $api->requireAction('dance'));

    logIn()->assertRedirect(config('oidc.login.home'));

    $this->assertAuthenticatedAs($user, 'identity');
});

it('clears a pipeline action once its screen reports it done', function (): void {
    Event::fake([RequiredActionCompleted::class]);
    $user = unverifiedUser();
    $user->forceFill(['email_verified_at' => now()])->save();
    app(PostLoginPipeline::class)->register(fn (LoginEvent $e, LoginApi $api) => $api->requireAction('verify_email'));

    logIn()->assertRedirect(route('identity.verification.notice'));

    $this->get(route('identity.verification.notice'))->assertRedirect(config('oidc.login.home'));

    $this->assertAuthenticatedAs($user->fresh(), 'identity');
    Event::assertDispatched(RequiredActionCompleted::class);
});

it('walks the user through several open actions in registration order', function (): void {
    config(['oidc.authentication.email_verification_required' => true]);
    $user = unverifiedUser();

    app(RequiredActionRegistry::class)->register(new class implements RequiredAction
    {
        public function key(): string
        {
            return 'read_the_terms';
        }

        public function isPending(Authenticatable $user, Realm $realm): bool
        {
            return true;
        }

        public function route(): string
        {
            return 'identity.login';
        }
    });

    logIn()->assertRedirect(route('identity.verification.notice'));

    expect(app(PendingActions::class)->for($user))->toBe(['verify_email', 'read_the_terms']);

    $this->get(verificationUrl($user));

    $this->assertGuest('identity');
    expect(app(PendingActions::class)->for($user->fresh()))->toBe(['read_the_terms']);
});
