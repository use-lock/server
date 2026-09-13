<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\Http\Controllers;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;
use Lock\Server\Authentication\Actions\ResetPassword;
use Lock\Server\Authentication\Concerns\ResolvesIdentityGuard;
use Lock\Server\Authentication\LoginOutcome;
use Lock\Server\Authentication\Pipeline\InteractiveLoginFinalizer;
use Lock\Server\Authentication\Ui\Views\PasswordResetPrompt;
use Lock\Server\Authentication\Ui\Views\PasswordResetView;
use Lock\Server\Shared\Authentication\PendingActions;
use Symfony\Component\HttpFoundation\Response;

class NewPasswordController
{
    use ResolvesIdentityGuard;

    public function __construct(
        private readonly ResetPassword $reset,
        private readonly InteractiveLoginFinalizer $finalizer,
        private readonly PendingActions $actions,
    ) {}

    /**
     * PasswordResetView is resolved here (not via the constructor) so
     * store() — which shares this class — never eagerly resolves a view the
     * request doesn't render.
     */
    public function create(Request $request): Responsable|Response
    {
        $email = $request->input('email');
        $status = $request->session()->get('status');

        return app(PasswordResetView::class)->respond(new PasswordResetPrompt(
            token: (string) $request->route('token'),
            email: is_string($email) ? $email : null,
            status: is_string($status) ? $status : null,
        ), $request);
    }

    public function store(Request $request): JsonResponse|RedirectResponse
    {
        // `confirmed` is checked here, before the broker validates the token:
        // the shipped reset page renders a confirmation field, and without
        // the rule a typo would silently commit the first value. The realm's
        // password policy is applied by the reset action once the token holds.
        $request->validate([
            'token' => ['required'],
            'email' => ['required', 'email'],
            'password' => ['required', 'confirmed'],
        ]);

        $result = ($this->reset)($request->all());

        if ($result->user instanceof Authenticatable) {
            // The password is reset either way; a postLogin denial or pending
            // second factor only affects the session that follows.
            $outcome = $this->finalizer->finalize($request, $result->user, 'pwd');

            if ($outcome === LoginOutcome::MfaChallenge) {
                return $request->wantsJson()
                    ? new JsonResponse(['two_factor' => true])
                    : redirect()->route('identity.two-factor.login');
            }

            if ($outcome === LoginOutcome::RequiredAction) {
                return $request->wantsJson()
                    ? new JsonResponse(['required_actions' => $this->actions->for($result->user)])
                    : redirect()->to($this->actions->url($result->user) ?? route('identity.login'));
            }

            return $request->wantsJson()
                ? new JsonResponse(['status' => __($result->status)], 200)
                : redirect()->route('identity.login')->with('status', __($result->status));
        }

        if ($request->wantsJson()) {
            throw ValidationException::withMessages(['email' => [__($result->status)]]);
        }

        return back()->withInput($request->only('email'))->withErrors(['email' => __($result->status)]);
    }
}
