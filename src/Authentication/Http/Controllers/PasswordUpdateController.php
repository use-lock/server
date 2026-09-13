<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\Http\Controllers;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\CanResetPassword;
use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Lock\Server\Authentication\Actions\UpdatePassword;
use Lock\Server\Authentication\Contracts\LoginFinalizer;
use Lock\Server\Authentication\RequiredActions\ContinuesLogin;
use Lock\Server\Authentication\RequiredActions\PendingRequiredActions;
use Lock\Server\Authentication\Ui\Views\PasswordUpdatePrompt;
use Lock\Server\Authentication\Ui\Views\PasswordUpdateView;
use Lock\Server\Shared\Authentication\PendingActions;
use Lock\Server\Shared\Authentication\RequiredActionSubject;
use Lock\Server\Shared\Credentials\PasswordCredential;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\HttpException;

/**
 * Changing the password of a user who is already identified. It is reachable
 * from the account screen and it is where an expired password lands, which is
 * why it sits behind the action subject rather than the guard.
 *
 * The current password is asked for from a live session and not mid-login:
 * there, the user proved a credential seconds ago, and a login that reached
 * here through a passkey or an upstream provider may have no password to
 * recite in the first place.
 */
class PasswordUpdateController
{
    use ContinuesLogin;

    public function __construct(
        private readonly UpdatePassword $updatePassword,
        private readonly RequiredActionSubject $subject,
        private readonly PasswordCredential $passwords,
        private readonly LoginFinalizer $finalizer,
        private readonly PendingActions $actions,
    ) {}

    /**
     * PasswordUpdateView is resolved here (not via the constructor) so
     * store() — which shares this class — never eagerly resolves a view the
     * request doesn't render.
     */
    public function create(Request $request): Responsable|Response
    {
        $user = $this->requireSubject($request);
        $status = $request->session()->get('status');

        return app(PasswordUpdateView::class)->respond(new PasswordUpdatePrompt(
            requiresCurrentPassword: $this->requiresCurrentPassword(),
            expired: $this->passwords->isExpired($user),
            status: is_string($status) ? $status : null,
        ), $request);
    }

    public function store(Request $request): JsonResponse|RedirectResponse
    {
        // Changing a password without a bound ResetUserPassword action is
        // disabled, not broken — so 404, as registration answers.
        abort_unless($this->updatePassword->enabled(), 404);

        $user = $this->requireSubject($request);

        $rules = ['password' => ['required', 'string', 'confirmed']];

        if ($this->requiresCurrentPassword()) {
            $rules['current_password'] = ['required', 'string', 'current_password:'.$this->guardName()];
        }

        $request->validate($rules);

        ($this->updatePassword)($user, $request->all());

        if ($request->wantsJson()) {
            return new JsonResponse('', 200);
        }

        return $this->continueAfterAction($request, $user, 'update_password');
    }

    private function requiresCurrentPassword(): bool
    {
        return ! PendingRequiredActions::find() instanceof PendingRequiredActions;
    }

    private function requireSubject(Request $request): Authenticatable&CanResetPassword
    {
        $user = $this->subject->current($request);

        if (! $user instanceof Authenticatable || ! $user instanceof CanResetPassword) {
            throw new HttpException(403);
        }

        return $user;
    }

    private function loginFinalizer(): LoginFinalizer
    {
        return $this->finalizer;
    }

    private function pendingActions(): PendingActions
    {
        return $this->actions;
    }
}
