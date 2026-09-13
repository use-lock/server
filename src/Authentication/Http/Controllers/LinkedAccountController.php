<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Lock\Server\Authentication\Concerns\ResolvesIdentityGuard;
use Lock\Server\Shared\Brokering\SocialAccounts;
use Lock\Server\Shared\Brokering\SocialProvider;
use Lock\Server\Shared\Brokering\SocialProviderRegistry;
use Lock\Server\Shared\Http\RespondsToInertiaExternalRedirects;
use Symfony\Component\HttpFoundation\Response;

class LinkedAccountController
{
    use ResolvesIdentityGuard;
    use RespondsToInertiaExternalRedirects;

    public function __construct(
        private readonly SocialProviderRegistry $providers,
        private readonly SocialAccounts $accounts,
    ) {}

    public function link(Request $request, string $provider): Response
    {
        $driver = $this->providers->get($provider) ?? abort(404);

        return $this->respondToInertia($request, $driver->redirect($request, SocialProvider::INTENT_LINK));
    }

    public function destroy(Request $request, string $socialAccount): JsonResponse|RedirectResponse
    {
        $user = $this->currentUser($request) ?? abort(401);

        $this->accounts->unlink($user, $socialAccount);

        return $this->statusResponse($request, 'social-account-unlinked', 200);
    }
}
