<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\Http\Controllers;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;
use Lock\Server\Authentication\Concerns\ResolvesIdentityGuard;
use Lock\Server\Authentication\Context\LoginState;
use Lock\Server\Authentication\Contracts\LoginFinalizer;
use Lock\Server\Authentication\LoginOutcome;
use Lock\Server\Authentication\PendingMfaChallenge;
use Lock\Server\Authentication\Ui\Views\TwoFactorChallengePrompt;
use Lock\Server\Authentication\Ui\Views\TwoFactorChallengeView;
use Lock\Server\Shared\Authentication\PendingActions;
use Lock\Server\Shared\Credentials\FactorEnrollment;
use Lock\Server\Shared\Credentials\FactorOperations;
use Lock\Server\Shared\Credentials\FactorRegistry;
use Lock\Server\Shared\Credentials\FactorVerification;
use Symfony\Component\HttpFoundation\Response;

class TwoFactorChallengeController
{
    use ResolvesIdentityGuard;

    public function __construct(
        private readonly FactorRegistry $factors,
        private readonly LoginState $sessionState,
        private readonly FactorOperations $operations,
        private readonly LoginFinalizer $finalizer,
        private readonly PendingActions $actions,
    ) {}

    /**
     * TwoFactorChallengeView is resolved here (not via the constructor) so
     * store() — which shares this class — never eagerly resolves a view the
     * request doesn't render.
     */
    public function create(Request $request): Responsable|RedirectResponse|Response
    {
        $pending = PendingMfaChallenge::find();
        $user = $pending instanceof PendingMfaChallenge ? $this->challengedUser($pending) : null;

        if (! $pending instanceof PendingMfaChallenge || ! $user instanceof Authenticatable) {
            return redirect()->route('identity.login');
        }

        return app(TwoFactorChallengeView::class)->respond(new TwoFactorChallengePrompt(
            factor: $pending->factor,
            availableFactors: $this->factors->configuredChallengeableEnrollments($user),
            factorId: $pending->factorId,
        ), $request);
    }

    /**
     * Matching against configuredChallengeableEnrollments() validates
     * ownership, confirmation, and the challenge-provider allow-list in one
     * step; an unknown or unenrolled provider or enrollment is silently ignored.
     */
    public function selectFactor(Request $request, string $provider, ?string $enrollment = null): RedirectResponse
    {
        $pending = PendingMfaChallenge::find();
        $user = $pending instanceof PendingMfaChallenge ? $this->challengedUser($pending) : null;

        if (! $pending instanceof PendingMfaChallenge || ! $user instanceof Authenticatable) {
            return redirect()->route('identity.login');
        }

        foreach ($this->factors->configuredChallengeableEnrollments($user) as $available) {
            if ($available->providerKey === $provider && ($enrollment === null || $available->id === $enrollment)) {
                new PendingMfaChallenge(
                    userId: $pending->userId,
                    remember: $pending->remember,
                    factor: $available->providerKey,
                    factorId: $available->id,
                )->store();

                break;
            }
        }

        return redirect()->route('identity.two-factor.login');
    }

    /**
     * Challenge issuance and verification are separate requests by design —
     * options generated in the same request as the verification can never
     * match a real assertion.
     */
    public function options(Request $request): JsonResponse
    {
        $pending = PendingMfaChallenge::find();
        $user = $pending instanceof PendingMfaChallenge ? $this->challengedUser($pending) : null;

        if (! $pending instanceof PendingMfaChallenge || ! $user instanceof Authenticatable) {
            return new JsonResponse(['message' => 'No pending two-factor challenge.'], 401);
        }

        $enrollment = $this->pendingEnrollment($user, $pending->factor, $pending->factorId);

        if (! $enrollment instanceof FactorEnrollment) {
            return new JsonResponse(['message' => 'No pending two-factor challenge.'], 401);
        }

        $challenge = $this->factors->get($pending->factor)->beginChallenge($user, $enrollment);

        PendingMfaChallenge::storeChallengeState($challenge->privateState);

        return new JsonResponse($challenge->publicData);
    }

    public function store(Request $request): JsonResponse|RedirectResponse
    {
        $request->validate([
            'code' => ['nullable', 'string'],
            'recovery_code' => ['nullable', 'string'],
            'credential' => ['nullable', 'array'],
        ]);

        $pending = PendingMfaChallenge::find();
        $user = $pending instanceof PendingMfaChallenge ? $this->challengedUser($pending) : null;

        if (! $pending instanceof PendingMfaChallenge || ! $user instanceof Authenticatable) {
            return redirect()->route('identity.login');
        }

        $usesRecoveryCode = $request->filled('recovery_code');
        $verification = $this->operations->verify(
            $user,
            $pending->factor,
            $pending->factorId,
            $request->only('code', 'recovery_code', 'credential'),
            PendingMfaChallenge::pullChallengeState(),
        );

        if (! $verification instanceof FactorVerification) {
            $field = $usesRecoveryCode ? 'recovery_code' : 'code';

            throw ValidationException::withMessages([$field => __('The provided two factor authentication code was invalid.')]);
        }

        $this->sessionState->add(...$verification->amr);

        PendingMfaChallenge::forget();

        if ($this->finalizer->finish($request, $user, $pending->remember) === LoginOutcome::RequiredAction) {
            $target = $this->actions->url($user) ?? $this->homeUrl();

            return $request->wantsJson()
                ? new JsonResponse(['required_actions' => $this->actions->for($user), 'redirect' => $target])
                : redirect()->to($target);
        }

        if ($request->wantsJson()) {
            // A WebAuthn submit comes from the passkey ceremony script, which
            // navigates via the returned redirect target.
            return $request->filled('credential')
                ? new JsonResponse(['redirect' => redirect()->intended($this->homeUrl())->getTargetUrl()])
                : new JsonResponse('', 204);
        }

        return redirect()->intended($this->homeUrl());
    }

    private function challengedUser(PendingMfaChallenge $pending): ?Authenticatable
    {
        return $this->sessionGuard()->getProvider()->retrieveById($pending->userId);
    }

    private function pendingEnrollment(Authenticatable $user, string $providerKey, string $id): ?FactorEnrollment
    {
        foreach ($this->factors->get($providerKey)->enrollments($user) as $enrollment) {
            if ($id === '' || $enrollment->id === $id) {
                return $enrollment;
            }
        }

        return null;
    }
}
