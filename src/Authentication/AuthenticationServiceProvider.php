<?php

declare(strict_types=1);

namespace Lock\Server\Authentication;

use Illuminate\Auth\Events\Logout;
use Illuminate\Auth\Notifications\ResetPassword;
use Illuminate\Auth\Notifications\VerifyEmail;
use Illuminate\Auth\Passwords\PasswordBroker;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Auth\PasswordBroker as PasswordBrokerContract;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Facades\Date;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\URL;
use Illuminate\Support\ServiceProvider;
use Laravel\Passkeys\Passkeys;
use Lock\Server\Authentication\Actions\ResetPassword as ResetPasswordAction;
use Lock\Server\Authentication\Actions\SendPasswordResetLink;
use Lock\Server\Authentication\Context\LoginState;
use Lock\Server\Authentication\Contracts\DeviceRecognizer;
use Lock\Server\Authentication\Contracts\LoginFinalizer;
use Lock\Server\Authentication\Contracts\SecondFactorGate;
use Lock\Server\Authentication\Listeners\DeleteRealmData;
use Lock\Server\Authentication\Listeners\DeleteUserData;
use Lock\Server\Authentication\Listeners\DispatchLoggedOut;
use Lock\Server\Authentication\Models\PasswordResetToken;
use Lock\Server\Authentication\Pipeline\InteractiveLoginFinalizer;
use Lock\Server\Authentication\Pipeline\NullDeviceRecognizer;
use Lock\Server\Authentication\Pipeline\PostLoginPipeline;
use Lock\Server\Authentication\RequiredActions\ConfigureMfaAction;
use Lock\Server\Authentication\RequiredActions\DerivedPendingActions;
use Lock\Server\Authentication\RequiredActions\RequiredActionRegistry;
use Lock\Server\Authentication\RequiredActions\SessionRequiredActionSubject;
use Lock\Server\Authentication\RequiredActions\UpdatePasswordAction;
use Lock\Server\Authentication\RequiredActions\VerifyEmailAction;
use Lock\Server\Authentication\Ui\Pages\ConfirmPasswordPage;
use Lock\Server\Authentication\Ui\Pages\ForgotPasswordPage;
use Lock\Server\Authentication\Ui\Pages\LoginPage;
use Lock\Server\Authentication\Ui\Pages\RegisterPage;
use Lock\Server\Authentication\Ui\Pages\ResetPasswordPage;
use Lock\Server\Authentication\Ui\Pages\SetupTwoFactorPage;
use Lock\Server\Authentication\Ui\Pages\TwoFactorChallengePage;
use Lock\Server\Authentication\Ui\Pages\UpdatePasswordPage;
use Lock\Server\Authentication\Ui\Pages\VerifyEmailPage;
use Lock\Server\Authentication\Ui\Views\EmailVerificationView;
use Lock\Server\Authentication\Ui\Views\FactorSetupView;
use Lock\Server\Authentication\Ui\Views\LoginView;
use Lock\Server\Authentication\Ui\Views\PasswordConfirmationView;
use Lock\Server\Authentication\Ui\Views\PasswordResetRequestView;
use Lock\Server\Authentication\Ui\Views\PasswordResetView;
use Lock\Server\Authentication\Ui\Views\PasswordUpdateView;
use Lock\Server\Authentication\Ui\Views\RegisterView;
use Lock\Server\Authentication\Ui\Views\TwoFactorChallengeView;
use Lock\Server\Shared\Authentication\AcrResolver;
use Lock\Server\Shared\Authentication\IdentityGuard;
use Lock\Server\Shared\Authentication\LoginContext;
use Lock\Server\Shared\Authentication\PendingActions;
use Lock\Server\Shared\Authentication\RequiredActionSubject;
use Lock\Server\Shared\Maintenance\RealmDeleting;
use Lock\Server\Shared\Maintenance\UserDeleting;

class AuthenticationServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->tag([PasswordResetToken::class], 'oidc.prunable');

        $this->configurePasskeyLogin();

        $identityGuard = IdentityGuard::name();

        if (! config()->has("auth.guards.{$identityGuard}")) {
            config()->set("auth.guards.{$identityGuard}", [
                'driver' => 'session',
                'provider' => (string) config('oidc.auth.provider', 'users'),
            ]);
        }

        $this->app->bind(LoginContext::class, LoginState::class);
        $this->app->singleton(PostLoginPipeline::class);
        $this->app->singleton(SecondFactorGate::class, EnrolledFactorGate::class);
        $this->app->bind(RequiredActionSubject::class, SessionRequiredActionSubject::class);
        $this->app->singleton(LoginFinalizer::class, InteractiveLoginFinalizer::class);
        $this->app->singleton(DeviceRecognizer::class, NullDeviceRecognizer::class);
        $this->app->bind(AcrResolver::class, LevelOfAssuranceAcrResolver::class);
        $this->app->when([SendPasswordResetLink::class, ResetPasswordAction::class])
            ->needs(PasswordBrokerContract::class)
            ->give(fn (Application $app): PasswordBroker => new PasswordBroker(
                $app->make(PasswordResetTokens::class),
                $app->make(AuthFactory::class)->createUserProvider((string) config('oidc.auth.provider', 'users')),
                $app->make(Dispatcher::class),
            ));
        $this->app->singleton(RequiredActionRegistry::class, function (Application $app): RequiredActionRegistry {
            $registry = new RequiredActionRegistry;
            $registry->register(
                $app->make(VerifyEmailAction::class),
                $app->make(UpdatePasswordAction::class),
                $app->make(ConfigureMfaAction::class),
            );

            return $registry;
        });

        $this->app->singleton(PendingActions::class, DerivedPendingActions::class);

        $this->app->bind(TwoFactorChallengeView::class, TwoFactorChallengePage::class);
        $this->app->bind(FactorSetupView::class, SetupTwoFactorPage::class);
        $this->app->bind(LoginView::class, LoginPage::class);
        $this->app->bind(RegisterView::class, RegisterPage::class);
        $this->app->bind(PasswordResetRequestView::class, ForgotPasswordPage::class);
        $this->app->bind(PasswordResetView::class, ResetPasswordPage::class);
        $this->app->bind(EmailVerificationView::class, VerifyEmailPage::class);
        $this->app->bind(PasswordConfirmationView::class, ConfirmPasswordPage::class);
        $this->app->bind(PasswordUpdateView::class, UpdatePasswordPage::class);
    }

    public function boot(): void
    {
        Event::listen(UserDeleting::class, DeleteUserData::class);
        Event::listen(RealmDeleting::class, DeleteRealmData::class);

        Event::listen(Logout::class, DispatchLoggedOut::class);

        ResetPassword::createUrlUsing(fn (mixed $notifiable, string $token): string => route(
            'identity.password.reset',
            ['token' => $token, 'email' => $notifiable->getEmailForPasswordReset()],
        ));
        VerifyEmail::createUrlUsing(fn (mixed $notifiable): string => URL::temporarySignedRoute(
            'identity.verification.verify',
            Date::now()->addMinutes((int) config('auth.verification.expire', 60)),
            ['id' => $notifiable->getKey(), 'hash' => sha1($notifiable->getEmailForVerification())],
        ));
    }

    private function configurePasskeyLogin(): void
    {
        Passkeys::ignoreRoutes();

        config()->set('passkeys.guard', IdentityGuard::name());
        config()->set('passkeys.redirect', config('oidc.login.home', '/dashboard'));
        config()->set('passkeys.middleware', ['web']);
        config()->set('passkeys.management_middleware', []);
        config()->set('passkeys.throttle', 'throttle:5,1');
    }
}
