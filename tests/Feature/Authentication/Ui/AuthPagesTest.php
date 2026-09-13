<?php

declare(strict_types=1);

use Illuminate\Events\Dispatcher;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Route;
use Lock\Server\Authentication\Ui\Pages\ConfirmPasswordPage;
use Lock\Server\Authentication\Ui\Pages\ForgotPasswordPage;
use Lock\Server\Authentication\Ui\Pages\LoginPage;
use Lock\Server\Authentication\Ui\Pages\ResetPasswordPage;
use Lock\Server\Authentication\Ui\Pages\TwoFactorChallengePage;
use Lock\Server\Authentication\Ui\Pages\UpdatePasswordPage;
use Lock\Server\Authentication\Ui\Views\LoginPrompt;
use Lock\Server\Authentication\Ui\Views\LoginView;
use Lock\Server\Authentication\Ui\Views\PasswordResetPrompt;
use Lock\Server\Authentication\Ui\Views\PasswordResetRequestPrompt;
use Lock\Server\Authentication\Ui\Views\PasswordUpdatePrompt;
use Lock\Server\Authentication\Ui\Views\TwoFactorChallengePrompt;
use Lock\Server\Shared\Credentials\FactorEnrollment;
use Workbench\App\Models\User;

/**
 * Swaps both the router and the URL generator's collection so route() and
 * Route::has() agree on which routes are gone.
 *
 * @param  list<string>  $names
 */
function withoutRoutes(array $names): void
{
    $previous = Route::getRoutes();
    $router = new Router(new Dispatcher, app());
    Route::swap($router);

    foreach ($previous->getRoutes() as $route) {
        if (! in_array((string) $route->getName(), $names, true)) {
            $router->getRoutes()->add($route);
        }
    }

    $router->getRoutes()->refreshNameLookups();
    app('url')->setRoutes($router->getRoutes());
}

/**
 * The `two-factor-challenge` form's fields keyed by input name. The recovery-code
 * reveal is a client-side toggle driven by the `conditions` each field declares,
 * so the payload is the only place its wiring is observable without a browser.
 *
 * @return array<string, array<string, mixed>>
 */
function twoFactorChallengeFields(string $payload): array
{
    $decoded = json_decode($payload, true, flags: JSON_THROW_ON_ERROR);
    $schema = data_get($decoded, 'props.lattice.schema');
    $form = collect(is_array($schema) ? $schema : [])->firstWhere('id', 'two-factor-challenge');
    $fields = data_get($form, 'schema');

    return collect(is_array($fields) ? $fields : [])
        ->mapWithKeys(fn (mixed $field): array => [(string) data_get($field, 'props.name') => (array) data_get($field, 'props')])
        ->all();
}

it('serves this package\'s page through the server route for each auth view contract', function (string $routeName, array $parameters, string $titleKey, string $visitor): void {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('password')]);
    $request = match ($visitor) {
        'identity' => $this->actingAs($user, 'identity'),
        'pending-two-factor' => $this->withSession(['login.id' => $user->getAuthIdentifier(), 'login.factor' => 'totp']),
        default => $this,
    };

    $request->get(route($routeName, $parameters), ['X-Inertia' => 'true'])
        ->assertOk()
        ->assertSee(__($titleKey), false);
})->with([
    'login' => ['identity.login', [], 'oidc-ui::auth.login.title', 'guest'],
    'register' => ['identity.register', [], 'oidc-ui::auth.register.title', 'guest'],
    'forgot-password' => ['identity.password.request', [], 'oidc-ui::auth.forgot-password.title', 'guest'],
    'reset-password' => ['identity.password.reset', ['token' => 'dummy-token'], 'oidc-ui::auth.reset-password.title', 'guest'],
    'verify-email' => ['identity.verification.notice', [], 'oidc-ui::auth.verify-email.title', 'identity'],
    'confirm-password' => ['identity.password.confirm', [], 'oidc-ui::auth.confirm-password.title', 'identity'],
    'two-factor-challenge' => ['identity.two-factor.login', [], 'oidc-ui::auth.two-factor.title', 'pending-two-factor'],
]);

it('lets a host application override a bound view contract', function (): void {
    $this->app->bind(LoginView::class, fn (): LoginView => new class implements LoginView
    {
        public function respond(LoginPrompt $prompt, Request $request): JsonResponse
        {
            return response()->json(['view' => 'fake-login']);
        }
    });

    $this->get(route('identity.login'), ['X-Inertia' => 'true'])
        ->assertOk()
        ->assertExactJson(['view' => 'fake-login']);
});

it('offers passkey sign-in on the login page only while the passkey endpoints exist', function (): void {
    expect(renderPage(new LoginPage))->toContain('passkey-verify');

    withoutRoutes(['identity.passkey.login-options', 'identity.passkey.login']);

    expect(renderPage(new LoginPage))->not->toContain('passkey-verify');
});

it('offers the sign-up prompt on the login page only while the register endpoint exists', function (): void {
    expect(renderPage(new LoginPage))->toContain(__('oidc-ui::auth.login.sign-up'));

    withoutRoutes(['identity.register', 'identity.register.store']);

    expect(renderPage(new LoginPage))->not->toContain(__('oidc-ui::auth.login.sign-up'));
});

it('offers the passkey ceremony on the confirm-password page only while the passkey endpoints exist', function (): void {
    expect(renderPage(new ConfirmPasswordPage))->toContain('passkey-verify');

    withoutRoutes(['identity.passkey.confirm-options', 'identity.passkey.confirm']);

    expect(renderPage(new ConfirmPasswordPage))->not->toContain('passkey-verify');
});

it('renders a login button per enabled social provider and no social section without one', function (): void {
    expect(renderPage(new LoginPage))->not->toContain('login-social');

    config()->set('oidc.social.providers.github.client_id', 'client-id');
    config()->set('oidc.social.providers.google.client_id', 'client-id');

    expect(renderPage(new LoginPage))
        ->toContain(__('oidc-ui::auth.login.social.divider'))
        ->toContain(__('oidc-ui::auth.login.social.github'))
        ->toContain(__('oidc-ui::auth.login.social.google'))
        ->toContain(str_replace('/', '\/', route('identity.social.redirect', ['provider' => 'github'], absolute: false)));
});

it('labels an unknown social provider with the fallback translation', function (): void {
    config()->set('oidc.social.providers.corp-sso', ['driver' => 'github', 'client_id' => 'client-id']);

    expect(renderPage(new LoginPage))
        ->toContain(__('oidc-ui::auth.login.social.fallback', ['provider' => 'Corp Sso']));
});

it('drops the social button icon when the provider icon is set to an empty string', function (): void {
    config()->set('oidc.social.providers.github.client_id', 'client-id');
    config()->set('oidc-ui.social_icons.github', '');

    expect(renderPage(new LoginPage))
        ->toContain(__('oidc-ui::auth.login.social.github'))
        ->not->toContain('"icon":"github"');
});

it('replaces the code input with the passkey ceremony and an always-visible recovery-code input on a webauthn challenge', function (): void {
    $payload = renderPage(new TwoFactorChallengePage(new TwoFactorChallengePrompt(factor: 'webauthn')));
    $fields = twoFactorChallengeFields($payload);

    expect($payload)->toContain('passkey-verify')
        ->and(array_keys($fields))->toBe(['recovery_code'])
        ->and($fields['recovery_code']['conditions'])->toBeNull();
});

it('renders the code input with a recovery-code reveal toggle on a code-based challenge', function (): void {
    $payload = renderPage(new TwoFactorChallengePage(new TwoFactorChallengePrompt(factor: 'totp')));
    $fields = twoFactorChallengeFields($payload);

    expect($payload)->not->toContain('passkey-verify')
        ->and($payload)->toContain('field.otp')
        ->and(array_keys($fields))->toBe(['code', 'recovery_code', 'use_recovery_code'])
        // The checkbox is the only way back to the code input, so it must never hide itself.
        ->and($fields['use_recovery_code']['conditions'])->toBeNull()
        ->and($fields['code']['conditions'])->toMatchArray([
            'visible' => [['field' => 'use_recovery_code', 'operator' => 'eq', 'value' => false]],
        ])
        ->and($fields['recovery_code']['conditions'])->toMatchArray([
            'visible' => [['field' => 'use_recovery_code', 'operator' => 'eq', 'value' => true]],
        ]);
});

it('lists the other enrolled methods only on a multi-provider challenge', function (): void {
    $multiProvider = renderPage(new TwoFactorChallengePage(new TwoFactorChallengePrompt(factor: 'totp', availableFactors: [
        new FactorEnrollment('totp', '1', 'Authenticator', now(), null),
        new FactorEnrollment('webauthn', '2', 'Security key', now(), null),
    ])));
    $singleProvider = renderPage(new TwoFactorChallengePage(new TwoFactorChallengePrompt(factor: 'totp', availableFactors: [
        new FactorEnrollment('totp', '1', 'Authenticator', now(), null),
    ])));

    expect($multiProvider)->toContain(__('oidc-ui::auth.two-factor.use-another'))
        ->and($multiProvider)->toContain(__('oidc-ui::auth.two-factor.method.webauthn'))
        // Inertia JSON escapes forward slashes, so the href is matched escaped.
        ->and($multiProvider)->toContain('two-factor-challenge\/factor\/webauthn')
        ->and($multiProvider)->not->toContain('two-factor-challenge\/factor\/totp')
        ->and($singleProvider)->not->toContain(__('oidc-ui::auth.two-factor.use-another'));
});

it('falls back to the code form for an unknown provider and still offers the known ones', function (): void {
    $content = renderPage(new TwoFactorChallengePage(new TwoFactorChallengePrompt(factor: 'sms', availableFactors: [
        new FactorEnrollment('sms', '1', 'Phone', now(), null),
        new FactorEnrollment('totp', '2', 'Authenticator', now(), null),
    ])));

    expect($content)->toContain('field.otp')
        ->and($content)->not->toContain('passkey-verify')
        ->and($content)->toContain(__('oidc-ui::auth.two-factor.method.totp'));
});

it('threads the prompt status through the forgot-password form', function (): void {
    $content = renderPage(new ForgotPasswordPage(new PasswordResetRequestPrompt(status: 'A reset link was sent to your inbox.')));

    expect($content)->toContain('A reset link was sent to your inbox.');
});

it('prefills the reset-password form with the prompt token and email', function (): void {
    $content = renderPage(new ResetPasswordPage(new PasswordResetPrompt(token: 'reset-token-123', email: 'reset-user@example.com')));

    expect($content)->toContain('"name":"token"')
        ->and($content)->toContain('"value":"reset-token-123"')
        ->and($content)->toContain('reset-user@example.com');
});

it('shows the log-out link on the verify-email page only while the configured logout route exists', function (): void {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('password')]);
    $this->actingAs($user, 'identity');

    $this->get(route('identity.verification.notice'), ['X-Inertia' => 'true'])
        ->assertOk()
        ->assertSee(__('oidc-ui::common.action.log-out'), false);

    config(['oidc-ui.logout_route' => 'route-that-does-not-exist']);

    $this->get(route('identity.verification.notice'), ['X-Inertia' => 'true'])
        ->assertOk()
        ->assertDontSee(__('oidc-ui::common.action.log-out'), false);
});

it('asks for the current password only when the server will accept one', function (): void {
    expect(renderPage(new UpdatePasswordPage(new PasswordUpdatePrompt(requiresCurrentPassword: true))))
        ->toContain(__('oidc-ui::auth.update-password.current'));

    expect(renderPage(new UpdatePasswordPage(new PasswordUpdatePrompt(requiresCurrentPassword: false))))
        ->not->toContain(__('oidc-ui::auth.update-password.current'));
});

it('says why the user is on the change-password page when the password expired', function (): void {
    expect(renderPage(new UpdatePasswordPage(new PasswordUpdatePrompt(requiresCurrentPassword: false, expired: true))))
        ->toContain(__('oidc-ui::auth.update-password.subtitle-expired'));

    expect(renderPage(new UpdatePasswordPage(new PasswordUpdatePrompt(requiresCurrentPassword: true))))
        ->toContain(__('oidc-ui::auth.update-password.subtitle'));
});
