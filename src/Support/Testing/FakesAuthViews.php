<?php

declare(strict_types=1);

namespace Lock\Server\Support\Testing;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Lock\Server\Authentication\Ui\Views\EmailVerificationPrompt;
use Lock\Server\Authentication\Ui\Views\EmailVerificationView;
use Lock\Server\Authentication\Ui\Views\FactorSetupPrompt;
use Lock\Server\Authentication\Ui\Views\FactorSetupView;
use Lock\Server\Authentication\Ui\Views\LoginPrompt;
use Lock\Server\Authentication\Ui\Views\LoginView;
use Lock\Server\Authentication\Ui\Views\PasswordConfirmationView;
use Lock\Server\Authentication\Ui\Views\PasswordResetPrompt;
use Lock\Server\Authentication\Ui\Views\PasswordResetRequestPrompt;
use Lock\Server\Authentication\Ui\Views\PasswordResetRequestView;
use Lock\Server\Authentication\Ui\Views\PasswordResetView;
use Lock\Server\Authentication\Ui\Views\PasswordUpdatePrompt;
use Lock\Server\Authentication\Ui\Views\PasswordUpdateView;
use Lock\Server\Authentication\Ui\Views\RegisterView;
use Lock\Server\Authentication\Ui\Views\TwoFactorChallengePrompt;
use Lock\Server\Authentication\Ui\Views\TwoFactorChallengeView;
use Lock\Server\Protocol\Ui\Views\LogoutConfirmationView;
use Lock\Server\Protocol\Ui\Views\LogoutPrompt;
use Lock\Server\Shared\Consents\ConsentPrompt;
use Lock\Server\Shared\Consents\ConsentView;

/**
 * Binds every auth view contract to a minimal JSON responder so engine tests
 * can drive the real controllers without rendering UI pages. Add to your Pest suite with
 * `uses(FakesAuthViews::class)` (or `use` it in a PHPUnit TestCase), then call
 * `fakeAuthViews()` before hitting a GET route for one of the views.
 */
trait FakesAuthViews
{
    protected function fakeAuthViews(): static
    {
        app()->bind(LoginView::class, fn (): LoginView => new class implements LoginView
        {
            public function respond(LoginPrompt $prompt, Request $request): JsonResponse
            {
                return response()->json(['view' => 'login', 'prompt' => get_object_vars($prompt)]);
            }
        });

        app()->bind(PasswordUpdateView::class, fn (): PasswordUpdateView => new class implements PasswordUpdateView
        {
            public function respond(PasswordUpdatePrompt $prompt, Request $request): JsonResponse
            {
                return response()->json(['view' => 'update-password', 'prompt' => get_object_vars($prompt)]);
            }
        });

        app()->bind(FactorSetupView::class, fn (): FactorSetupView => new class implements FactorSetupView
        {
            public function respond(FactorSetupPrompt $prompt, Request $request): JsonResponse
            {
                return response()->json([
                    'view' => 'two-factor-setup',
                    'prompt' => [
                        'required' => $prompt->required,
                        'enrolled' => $prompt->enrolled,
                        'options' => array_column($prompt->options, 'id'),
                    ],
                ]);
            }
        });

        app()->bind(RegisterView::class, fn (): RegisterView => new class implements RegisterView
        {
            public function respond(Request $request): JsonResponse
            {
                return response()->json(['view' => 'register']);
            }
        });

        app()->bind(PasswordResetRequestView::class, fn (): PasswordResetRequestView => new class implements PasswordResetRequestView
        {
            public function respond(PasswordResetRequestPrompt $prompt, Request $request): JsonResponse
            {
                return response()->json(['view' => 'request-password-reset-link', 'prompt' => get_object_vars($prompt)]);
            }
        });

        app()->bind(PasswordResetView::class, fn (): PasswordResetView => new class implements PasswordResetView
        {
            public function respond(PasswordResetPrompt $prompt, Request $request): JsonResponse
            {
                return response()->json(['view' => 'reset-password', 'prompt' => get_object_vars($prompt)]);
            }
        });

        app()->bind(EmailVerificationView::class, fn (): EmailVerificationView => new class implements EmailVerificationView
        {
            public function respond(EmailVerificationPrompt $prompt, Request $request): JsonResponse
            {
                return response()->json(['view' => 'verify-email', 'prompt' => get_object_vars($prompt)]);
            }
        });

        app()->bind(PasswordConfirmationView::class, fn (): PasswordConfirmationView => new class implements PasswordConfirmationView
        {
            public function respond(Request $request): JsonResponse
            {
                return response()->json(['view' => 'confirm-password']);
            }
        });

        app()->bind(TwoFactorChallengeView::class, fn (): TwoFactorChallengeView => new class implements TwoFactorChallengeView
        {
            public function respond(TwoFactorChallengePrompt $prompt, Request $request): JsonResponse
            {
                return response()->json(['view' => 'two-factor-challenge', 'prompt' => get_object_vars($prompt)]);
            }
        });

        app()->bind(ConsentView::class, fn (): ConsentView => new class implements ConsentView
        {
            public function respond(ConsentPrompt $prompt, Request $request): JsonResponse
            {
                return response()->json(['view' => 'consent', 'prompt' => get_object_vars($prompt)]);
            }
        });

        app()->bind(LogoutConfirmationView::class, fn (): LogoutConfirmationView => new class implements LogoutConfirmationView
        {
            public function respond(LogoutPrompt $prompt, Request $request): JsonResponse
            {
                return response()->json(['view' => 'logout-confirmation', 'prompt' => get_object_vars($prompt)]);
            }
        });

        return $this;
    }
}
