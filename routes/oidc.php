<?php

declare(strict_types=1);

use Illuminate\Cookie\Middleware\AddQueuedCookiesToResponse;
use Illuminate\Cookie\Middleware\EncryptCookies;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Facades\Route;
use Illuminate\View\Middleware\ShareErrorsFromSession;
use Laravel\Passkeys\Http\Controllers\PasskeyConfirmationController;
use Laravel\Passkeys\Http\Controllers\PasskeyLoginController;
use Lock\Server\Authentication\Http\Controllers\AuthenticatedSessionController;
use Lock\Server\Authentication\Http\Controllers\ConfirmablePasswordController;
use Lock\Server\Authentication\Http\Controllers\EmailVerificationPromptController;
use Lock\Server\Authentication\Http\Controllers\FactorEnrollmentController;
use Lock\Server\Authentication\Http\Controllers\LinkedAccountController;
use Lock\Server\Authentication\Http\Controllers\NewPasswordController;
use Lock\Server\Authentication\Http\Controllers\PasskeyAuthenticatedSessionController;
use Lock\Server\Authentication\Http\Controllers\PasswordResetLinkController;
use Lock\Server\Authentication\Http\Controllers\PasswordUpdateController;
use Lock\Server\Authentication\Http\Controllers\RegisteredUserController;
use Lock\Server\Authentication\Http\Controllers\SendEmailVerificationNotificationController;
use Lock\Server\Authentication\Http\Controllers\ShowConfirmedPasswordStatusController;
use Lock\Server\Authentication\Http\Controllers\SocialAuthenticationController;
use Lock\Server\Authentication\Http\Controllers\TwoFactorChallengeController;
use Lock\Server\Authentication\Http\Controllers\VerifyEmailController;
use Lock\Server\Authentication\Http\Middleware\AuthenticateIdentity;
use Lock\Server\Authentication\Http\Middleware\ConfirmPassword;
use Lock\Server\Authentication\Http\Middleware\RequireActionSubject;
use Lock\Server\Authentication\Http\Middleware\RequireLoginMethod;
use Lock\Server\Protocol\Http\Controllers\ApproveConsentController;
use Lock\Server\Protocol\Http\Controllers\AuthorizationServerMetadataController;
use Lock\Server\Protocol\Http\Controllers\AuthorizeController;
use Lock\Server\Protocol\Http\Controllers\ClientRegistrationController;
use Lock\Server\Protocol\Http\Controllers\DenyConsentController;
use Lock\Server\Protocol\Http\Controllers\DiscoveryController;
use Lock\Server\Protocol\Http\Controllers\EndSessionController;
use Lock\Server\Protocol\Http\Controllers\IntrospectionController;
use Lock\Server\Protocol\Http\Controllers\JwksController;
use Lock\Server\Protocol\Http\Controllers\ProtectedResourceController;
use Lock\Server\Protocol\Http\Controllers\RevocationController;
use Lock\Server\Protocol\Http\Controllers\TokenController;
use Lock\Server\Protocol\Http\Controllers\UserinfoController;
use Lock\Server\Realms\Enums\RealmRouting;
use Lock\Server\Realms\Http\Middleware\ResolveRealm;
use Lock\Server\Shared\Authentication\IdentityGuard;

$guard = IdentityGuard::name();
$guest = 'guest:'.$guard;
$authenticated = AuthenticateIdentity::class.':'.$guard;
// A required action is settled either mid-login, before any session exists,
// or from a live one — so its screens sit behind the subject, not the guard.
$actionSubject = RequireActionSubject::class;
$passwordConfirmed = ConfirmPassword::using('identity.password.confirm');
$password = RequireLoginMethod::class.':password';
$passkey = RequireLoginMethod::class.':passkey';
$social = RequireLoginMethod::class.':social';

/** @var array<int, string> $shared */
$shared = (array) config('oidc.routes.middleware', []);
/** @var array<int, string> $screens */
$screens = (array) config('oidc.routes.screen_middleware', []);
$routing = RealmRouting::configured();

Route::middleware([ResolveRealm::class, ...$shared])
    ->prefix($routing->prefix())
    ->where(['realm' => '[A-Za-z0-9._-]+'])
    ->group(function () use ($guest, $authenticated, $passwordConfirmed, $password, $passkey, $social, $actionSubject, $screens): void {
        Route::middleware(['web', ...$screens])->group(function () use ($guest, $authenticated, $passwordConfirmed, $password, $passkey, $social, $actionSubject): void {
            Route::middleware($guest)->group(function () use ($password, $passkey, $social): void {
                Route::get('auth/login', [AuthenticatedSessionController::class, 'create'])->name('identity.login');
                Route::get('auth/register', [RegisteredUserController::class, 'create'])->middleware($password)->name('identity.register');
                Route::get('auth/forgot-password', [PasswordResetLinkController::class, 'create'])->middleware($password)->name('identity.password.request');
                Route::get('auth/reset-password/{token}', [NewPasswordController::class, 'create'])->middleware($password)->name('identity.password.reset');
                Route::get('auth/two-factor-challenge', [TwoFactorChallengeController::class, 'create'])->name('identity.two-factor.login');
                Route::get('auth/two-factor-challenge/factor/{provider}/{enrollment?}', [TwoFactorChallengeController::class, 'selectFactor'])->name('identity.two-factor.login.factor');
                Route::get('auth/social/{provider}', [SocialAuthenticationController::class, 'redirect'])->middleware($social)->name('identity.social.redirect');

                Route::middleware('throttle:5,1')->group(function () use ($password, $passkey): void {
                    Route::post('auth/login', [AuthenticatedSessionController::class, 'store'])->middleware($password)->name('identity.login.store');
                    Route::post('auth/register', [RegisteredUserController::class, 'store'])->middleware($password)->name('identity.register.store');
                    Route::post('auth/forgot-password', [PasswordResetLinkController::class, 'store'])->middleware($password)->name('identity.password.email');
                    Route::post('auth/reset-password', [NewPasswordController::class, 'store'])->middleware($password)->name('identity.password.update');
                    Route::post('auth/two-factor-challenge', [TwoFactorChallengeController::class, 'store'])->name('identity.two-factor.login.store');
                    Route::get('auth/two-factor-challenge/options', [TwoFactorChallengeController::class, 'options'])->name('identity.two-factor.login.options');
                    Route::get('auth/passkeys/login/options', [PasskeyLoginController::class, 'index'])->middleware($passkey)->name('identity.passkey.login-options');
                    Route::post('auth/passkeys/login', [PasskeyAuthenticatedSessionController::class, 'store'])->middleware($passkey)->name('identity.passkey.login');
                });
            });

            Route::middleware([$actionSubject, $passwordConfirmed])->group(function (): void {
                Route::get('auth/user/two-factor/setup', [FactorEnrollmentController::class, 'setup'])->name('identity.two-factor.setup');
                Route::get('auth/user/two-factor/factors', [FactorEnrollmentController::class, 'index'])->name('identity.two-factor.factors');
                Route::post('auth/user/two-factor/{provider}', [FactorEnrollmentController::class, 'store'])->middleware('throttle:5,1')->name('identity.two-factor.enroll');
                Route::post('auth/user/two-factor/{provider}/confirm', [FactorEnrollmentController::class, 'confirm'])->middleware('throttle:5,1')->name('identity.two-factor.enroll.confirm');
                Route::post('auth/user/two-factor/setup/continue', [FactorEnrollmentController::class, 'resume'])->name('identity.two-factor.setup.continue');
            });

            Route::middleware($actionSubject)->group(function () use ($password): void {
                Route::get('auth/user/password', [PasswordUpdateController::class, 'create'])->middleware($password)->name('identity.password.change');
                Route::post('auth/user/password', [PasswordUpdateController::class, 'store'])->middleware([$password, 'throttle:5,1'])->name('identity.password.change.store');

                Route::get('auth/email/verify', EmailVerificationPromptController::class)->name('identity.verification.notice');
                Route::get('auth/email/verify/{id}/{hash}', VerifyEmailController::class)->middleware(['signed', 'throttle:6,1'])->name('identity.verification.verify');
                Route::post('auth/email/verification-notification', SendEmailVerificationNotificationController::class)->middleware('throttle:6,1')->name('identity.verification.send');
            });

            Route::middleware($authenticated)->group(function () use ($passwordConfirmed, $social): void {
                Route::get('auth/user/confirm-password', [ConfirmablePasswordController::class, 'show'])->name('identity.password.confirm');
                Route::post('auth/user/confirm-password', [ConfirmablePasswordController::class, 'store'])->middleware('throttle:5,1')->name('identity.password.confirm.store');
                Route::get('auth/user/confirmed-password-status', ShowConfirmedPasswordStatusController::class)->name('identity.password.confirmation');

                Route::get('auth/passkeys/confirm/options', [PasskeyConfirmationController::class, 'index'])->middleware('throttle:5,1')->name('identity.passkey.confirm-options');
                Route::post('auth/passkeys/confirm', [PasskeyConfirmationController::class, 'store'])->middleware('throttle:5,1')->name('identity.passkey.confirm');

                Route::middleware($passwordConfirmed)->group(function () use ($social): void {
                    Route::delete('auth/user/two-factor/{provider}/{enrollment}', [FactorEnrollmentController::class, 'destroy'])->name('identity.two-factor.revoke');

                    Route::get('auth/user/social/{provider}', [LinkedAccountController::class, 'link'])->middleware($social)->name('identity.social.link');
                    Route::delete('auth/user/social/{socialAccount}', [LinkedAccountController::class, 'destroy'])->name('identity.social.destroy');
                });
            });

            Route::match(['get', 'post'], 'oauth/authorize', AuthorizeController::class)->name('oidc.authorize');
            Route::match(['get', 'post'], 'oauth/logout', EndSessionController::class)->name('oidc.logout');

            Route::middleware($authenticated)->group(function (): void {
                Route::post('oauth/authorize/consent', ApproveConsentController::class)->name('oidc.approve');
                Route::delete('oauth/authorize/consent', DenyConsentController::class)->name('oidc.deny');
            });
        });

        // The identity provider must keep issuing tokens while a third party's
        // cookie is absent, so these carry no session middleware.
        Route::match(['get', 'post'], 'auth/social/{provider}/callback', [SocialAuthenticationController::class, 'callback'])
            ->middleware([EncryptCookies::class, AddQueuedCookiesToResponse::class, StartSession::class, ShareErrorsFromSession::class, $social])
            ->name('identity.social.callback');

        Route::get('.well-known/jwks.json', JwksController::class)->name('oidc.jwks');
        Route::get('.well-known/openid-configuration', DiscoveryController::class)->name('oidc.discovery');
        Route::match(['get', 'post'], 'oauth/userinfo', UserinfoController::class)->name('oidc.userinfo');

        Route::middleware('throttle')->group(function (): void {
            Route::post('oauth/token', TokenController::class)->name('oidc.token');
            Route::post('oauth/introspect', IntrospectionController::class)->name('oidc.introspect');
            Route::post('oauth/revoke', RevocationController::class)->name('oidc.revoke');

            Route::post('oauth/register', ClientRegistrationController::class)->name('oidc.register');
        });
    });

/**
 * RFC 8414 §3.1 and RFC 9728 §3.1 insert the well-known segment ahead of the
 * issuer's path rather than appending it, so these two sit outside the realm
 * prefix and carry the realm behind it.
 */
Route::middleware([ResolveRealm::class, ...$shared])
    ->where(['realm' => '[A-Za-z0-9._-]+'])
    ->group(function () use ($routing): void {
        Route::get('.well-known/oauth-authorization-server/'.$routing->wellKnownSuffix().'{path?}', AuthorizationServerMetadataController::class)
            ->where('path', '.*')
            ->name('oidc.authorization-server');
        Route::get('.well-known/oauth-protected-resource/'.$routing->wellKnownSuffix().'{path?}', ProtectedResourceController::class)
            ->where('path', '.*')
            ->name('oidc.protected-resource');
    });
