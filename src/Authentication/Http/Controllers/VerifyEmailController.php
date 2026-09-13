<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\Http\Controllers;

use Illuminate\Auth\Events\Verified;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Lock\Server\Authentication\Contracts\LoginFinalizer;
use Lock\Server\Authentication\RequiredActions\ContinuesLogin;
use Lock\Server\Shared\Authentication\PendingActions;
use Lock\Server\Shared\Authentication\RequiredActionSubject;
use Symfony\Component\HttpKernel\Exception\HttpException;

/**
 * The link is signed, but the signature only proves the URL was minted here.
 * Binding it to the id and the address hash is what stops one user's link
 * from confirming another's address, so the checks stay even though Laravel's
 * EmailVerificationRequest no longer performs them — that form request reads
 * the guard, and mid-login there is no session for it to read.
 */
class VerifyEmailController
{
    use ContinuesLogin;

    public function __construct(
        private readonly RequiredActionSubject $subject,
        private readonly LoginFinalizer $finalizer,
        private readonly PendingActions $actions,
    ) {}

    public function __invoke(Request $request, string $id, string $hash): RedirectResponse
    {
        $user = $this->subject->current($request);

        if (! $user instanceof MustVerifyEmail
            || ! hash_equals((string) $user->getAuthIdentifier(), $id)
            || ! hash_equals(sha1($user->getEmailForVerification()), $hash)) {
            throw new HttpException(403);
        }

        if (! $user->hasVerifiedEmail() && $user->markEmailAsVerified()) {
            event(new Verified($user));
        }

        $request->session()->put('url.intended', $this->intendedWithFlag($request));

        return $this->continueAfterAction($request, $user, 'verify_email');
    }

    /**
     * `?verified=1` is what the landing page reads to acknowledge the click,
     * so it has to survive being routed through any action still open.
     */
    private function intendedWithFlag(Request $request): string
    {
        $intended = $request->session()->get('url.intended');
        $target = is_string($intended) && $intended !== '' ? $intended : $this->homeUrl();

        return $target.(str_contains($target, '?') ? '&' : '?').'verified=1';
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
