<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\Http\Controllers;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Lock\Server\Authentication\Concerns\ResolvesIdentityGuard;
use Lock\Server\Authentication\Contracts\LoginFinalizer;
use Lock\Server\Authentication\LoginOutcome;
use Lock\Server\Shared\Authentication\PendingActions;
use Lock\Server\Shared\Brokering\InvalidStateException;
use Lock\Server\Shared\Brokering\SocialAccountAlreadyLinkedException;
use Lock\Server\Shared\Brokering\SocialAccounts;
use Lock\Server\Shared\Brokering\SocialAuthenticationException;
use Lock\Server\Shared\Brokering\SocialLoginFailed;
use Lock\Server\Shared\Brokering\SocialProvider;
use Lock\Server\Shared\Brokering\SocialProviderRegistry;
use Lock\Server\Shared\Brokering\SocialUser;
use Lock\Server\Shared\Http\RespondsToInertiaExternalRedirects;
use Symfony\Component\HttpFoundation\Response;

class SocialAuthenticationController
{
    use ResolvesIdentityGuard;
    use RespondsToInertiaExternalRedirects;

    public function __construct(
        private readonly SocialProviderRegistry $providers,
        private readonly SocialAccounts $accounts,
        private readonly LoginFinalizer $finalizer,
        private readonly PendingActions $actions,
    ) {}

    public function redirect(Request $request, string $provider): Response
    {
        return $this->respondToInertia($request, $this->provider($provider)->redirect($request));
    }

    public function callback(Request $request, string $provider): RedirectResponse
    {
        if ($request->isMethod('POST')) {
            // A cross-site form_post (Apple) is sent without the session
            // cookie under SameSite=Lax; bounce to a top-level GET, where the
            // cookie is sent and the state can be validated.
            return redirect()->to(
                $request->url().'?'.http_build_query($request->only(['code', 'state', 'error', 'user'])),
                303,
            );
        }

        $driver = $this->provider($provider);

        if ($request->filled('error')) {
            return $this->failed(__('The sign-in was cancelled or refused by the provider.'));
        }

        try {
            $callback = $driver->callback($request);

            return $callback->intent === SocialProvider::INTENT_LINK
                ? $this->completeLink($request, $provider, $callback->user)
                : $this->completeLogin($request, $provider, $callback->user);
        } catch (InvalidStateException) {
            return $this->failed(__('Your sign-in attempt expired. Please try again.'));
        } catch (SocialAuthenticationException $exception) {
            Log::warning("oidc: social authentication with [{$provider}] failed: {$exception->getMessage()}");
            event(new SocialLoginFailed($provider, $exception->getMessage()));

            return $this->failed(__('We could not sign you in with this account.'));
        }
    }

    private function completeLogin(Request $request, string $providerKey, SocialUser $socialUser): RedirectResponse
    {
        $guard = $this->sessionGuard();

        if ($guard->check()) {
            return redirect()->intended($this->homeUrl());
        }

        $user = $this->accounts->resolveUser($providerKey, $socialUser, $guard->getProvider());

        if (! $user instanceof Authenticatable) {
            return $this->failed(__('We could not sign you in with this account.'));
        }

        return match ($this->finalizer->finalize($request, $user, $providerKey)) {
            LoginOutcome::Denied => $this->failed(__('We could not sign you in with this account.')),
            LoginOutcome::MfaChallenge => redirect()->route('identity.two-factor.login'),
            LoginOutcome::RequiredAction => redirect()->to($this->actions->url($user) ?? $this->homeUrl()),
            LoginOutcome::LoggedIn => redirect()->intended($this->homeUrl()),
        };
    }

    private function completeLink(Request $request, string $providerKey, SocialUser $socialUser): RedirectResponse
    {
        $user = $this->currentUser($request);

        if (! $user instanceof Authenticatable) {
            return $this->failed(__('Please log in before linking an account.'));
        }

        try {
            $this->accounts->linkAccount($user, $providerKey, $socialUser);
        } catch (SocialAccountAlreadyLinkedException) {
            return redirect($this->homeUrl())->withErrors(['social' => __('This account is already linked to another user.')]);
        }

        return redirect($this->homeUrl())->with('status', 'social-account-linked');
    }

    private function provider(string $key): SocialProvider
    {
        return $this->providers->get($key) ?? abort(404);
    }

    private function failed(string $message): RedirectResponse
    {
        return redirect()->route('identity.login')->withErrors(['social' => $message]);
    }
}
