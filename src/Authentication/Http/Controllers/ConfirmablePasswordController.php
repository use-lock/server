<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\Http\Controllers;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;
use Lock\Server\Authentication\Actions\ConfirmPassword;
use Lock\Server\Authentication\Concerns\ResolvesIdentityGuard;
use Lock\Server\Authentication\Ui\Views\PasswordConfirmationView;
use Symfony\Component\HttpFoundation\Response;

class ConfirmablePasswordController
{
    use ResolvesIdentityGuard;

    public function __construct(private readonly ConfirmPassword $confirm) {}

    /**
     * PasswordConfirmationView is resolved here (not via the constructor) so
     * store() — which shares this class — never eagerly resolves a view the
     * request doesn't render.
     */
    public function show(Request $request): Responsable|Response
    {
        return app(PasswordConfirmationView::class)->respond($request);
    }

    public function store(Request $request): JsonResponse|RedirectResponse
    {
        $request->validate(['password' => ['required', 'string']]);

        $user = $this->currentUser($request);

        if (! $user instanceof Authenticatable || ! ($this->confirm)($user, $request->string('password')->value(), $request->session())) {
            throw ValidationException::withMessages(['password' => __('auth.password')]);
        }

        if ($request->wantsJson()) {
            return new JsonResponse('', 201);
        }

        return redirect()->intended($this->homeUrl());
    }
}
