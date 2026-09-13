<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\Http\Controllers;

use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Lock\Server\Authentication\Actions\SendEmailVerification;
use Lock\Server\Authentication\Concerns\ResolvesIdentityGuard;
use Lock\Server\Shared\Authentication\RequiredActionSubject;
use Symfony\Component\HttpKernel\Exception\HttpException;

class SendEmailVerificationNotificationController
{
    use ResolvesIdentityGuard;

    public function __construct(
        private readonly SendEmailVerification $sendVerification,
        private readonly RequiredActionSubject $subject,
    ) {}

    public function __invoke(Request $request): JsonResponse|RedirectResponse
    {
        $user = $this->subject->current($request);

        if (! $user instanceof MustVerifyEmail) {
            throw new HttpException(403);
        }

        if (! ($this->sendVerification)($user)) {
            return redirect()->intended($this->homeUrl());
        }

        if ($request->wantsJson()) {
            return new JsonResponse('', 202);
        }

        return back()->with('status', 'verification-link-sent');
    }
}
