<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\Http\Controllers;

use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Lock\Server\Authentication\Actions\RegisterUser;
use Lock\Server\Authentication\Concerns\ResolvesIdentityGuard;
use Lock\Server\Authentication\LoginOutcome;
use Lock\Server\Authentication\Pipeline\InteractiveLoginFinalizer;
use Lock\Server\Authentication\Ui\Views\RegisterView;
use Lock\Server\Shared\Authentication\PendingActions;
use Symfony\Component\HttpFoundation\Response;

class RegisteredUserController
{
    use ResolvesIdentityGuard;

    public function __construct(
        private readonly RegisterUser $register,
        private readonly InteractiveLoginFinalizer $finalizer,
        private readonly PendingActions $actions,
    ) {}

    /**
     * RegisterView is resolved here (not via the constructor) so store() —
     * which shares this class — never eagerly resolves a view the request
     * doesn't render.
     */
    public function create(Request $request): Responsable|Response
    {
        return app(RegisterView::class)->respond($request);
    }

    public function store(Request $request): JsonResponse|RedirectResponse
    {
        // Registration without a bound CreateUser action is disabled, not
        // broken — so 404, not 500.
        abort_unless($this->register->enabled(), 404);

        $user = ($this->register)($request->all());

        // The account exists either way; a postLogin denial only refuses the
        // session, so the user lands on the login page instead.
        return match ($this->finalizer->finalize($request, $user, 'pwd')) {
            LoginOutcome::Denied => $request->wantsJson()
                ? new JsonResponse('', 403)
                : redirect()->route('identity.login'),
            LoginOutcome::MfaChallenge => $request->wantsJson()
                ? new JsonResponse(['two_factor' => true])
                : redirect()->route('identity.two-factor.login'),
            LoginOutcome::RequiredAction => $request->wantsJson()
                ? new JsonResponse(['required_actions' => $this->actions->for($user)], 201)
                : redirect()->to($this->actions->url($user) ?? $this->homeUrl()),
            LoginOutcome::LoggedIn => $request->wantsJson()
                ? new JsonResponse('', 201)
                : redirect()->intended($this->homeUrl()),
        };
    }
}
