<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\Http\Controllers;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;
use Lock\Server\Authentication\Contracts\LoginFinalizer;
use Lock\Server\Authentication\RequiredActions\ContinuesLogin;
use Lock\Server\Authentication\RequiredActions\PendingRequiredActions;
use Lock\Server\Authentication\Ui\Views\FactorSetupPrompt;
use Lock\Server\Authentication\Ui\Views\FactorSetupView;
use Lock\Server\Shared\Authentication\PendingActions;
use Lock\Server\Shared\Authentication\RequiredActionSubject;
use Lock\Server\Shared\Credentials\EnrollableFactorProvider;
use Lock\Server\Shared\Credentials\EnrollmentOption;
use Lock\Server\Shared\Credentials\FactorEnrollment;
use Lock\Server\Shared\Credentials\FactorOperations;
use Lock\Server\Shared\Credentials\FactorRegistry;
use Symfony\Component\HttpFoundation\Response;

/**
 * The provider-keyed enrollment surface: any registered
 * {@see EnrollableFactorProvider} is enrollable through these endpoints
 * without package changes, including multi-step ceremonies (webauthn returns
 * its creation options in the begin metadata and takes the attestation
 * credential on confirm).
 */
class FactorEnrollmentController
{
    use ContinuesLogin;

    public function __construct(
        private readonly FactorRegistry $factors,
        private readonly FactorOperations $operations,
        private readonly RequiredActionSubject $subject,
        private readonly LoginFinalizer $finalizer,
        private readonly PendingActions $actions,
    ) {}

    /**
     * The enrollment page. It is where a realm that insists on a second
     * factor sends a user without one, so it is reachable mid-login as well
     * as from the account screen; the view is resolved here so the JSON
     * endpoints that share this class never resolve one.
     */
    public function setup(Request $request): Responsable|Response
    {
        $status = $request->session()->get('status');

        return app(FactorSetupView::class)->respond(new FactorSetupPrompt(
            options: $this->factors->enrollmentOptions(),
            required: PendingRequiredActions::find() instanceof PendingRequiredActions,
            enrolled: $this->factors->configuredChallengeableEnrollments($this->requireUser($request)) !== [],
            status: is_string($status) ? $status : null,
        ), $request);
    }

    public function index(Request $request): JsonResponse
    {
        $user = $this->requireUser($request);

        return new JsonResponse([
            'factors' => array_map(
                $this->serialize(...),
                $this->factors->enrollments($user),
            ),
        ]);
    }

    public function store(Request $request, string $provider): JsonResponse
    {
        $user = $this->requireUser($request);
        $name = $request->input('name');

        $enrollment = $this->operations->enroll(
            $user,
            $this->enrollable($provider),
            $this->requestedOption($request, $provider),
            is_string($name) && $name !== '' ? $name : null,
        );

        return new JsonResponse($this->serialize($enrollment), 201);
    }

    public function confirm(Request $request, string $provider): JsonResponse
    {
        $user = $this->requireUser($request);
        $enrollable = $this->enrollable($provider);
        $enrollment = $this->factors->findEnrollment($user, $provider, (string) $request->input('enrollment_id'));

        if (! $enrollment instanceof FactorEnrollment || ! $this->operations->confirm($user, $enrollable, $enrollment, $request->except('enrollment_id'))) {
            throw ValidationException::withMessages(['code' => __('The provided two factor authentication code was invalid.')]);
        }

        return new JsonResponse('', 200);
    }

    /**
     * Continues a login the realm was holding for a second factor. It is a
     * step of its own rather than a tail on confirm(), because a first factor
     * mints recovery codes that are shown once — redirecting off the page
     * that displays them would lose them.
     */
    public function resume(Request $request): RedirectResponse
    {
        $user = $this->requireUser($request);

        abort_unless($this->factors->configuredChallengeableEnrollments($user) !== [], 409);

        return $this->continueAfterAction($request, $user, 'configure_mfa');
    }

    public function destroy(Request $request, string $provider, string $enrollment): JsonResponse
    {
        $user = $this->requireUser($request);
        $enrollable = $this->enrollable($provider);
        $pending = $this->factors->findEnrollment($user, $provider, $enrollment) ?? abort(404);

        $this->operations->revoke($user, $enrollable, $pending);

        return new JsonResponse('', 204);
    }

    private function enrollable(string $provider): EnrollableFactorProvider
    {
        return $this->factors->enrollable($provider) ?? abort(404);
    }

    /**
     * Omitting the option keeps the provider's default, but an option that
     * belongs to a different provider is a client bug, not a fallback.
     */
    private function requestedOption(Request $request, string $provider): ?EnrollmentOption
    {
        $id = $request->input('option');

        if (! is_string($id) || $id === '') {
            return null;
        }

        $option = $this->factors->enrollmentOption($id);

        if (! $option instanceof EnrollmentOption || $option->providerKey !== $provider) {
            throw ValidationException::withMessages(['option' => __('The selected enrollment option is invalid.')]);
        }

        return $option;
    }

    private function requireUser(Request $request): Authenticatable
    {
        return $this->subject->current($request) ?? abort(401);
    }

    private function loginFinalizer(): LoginFinalizer
    {
        return $this->finalizer;
    }

    private function pendingActions(): PendingActions
    {
        return $this->actions;
    }

    /**
     * @return array<string, mixed>
     */
    private function serialize(FactorEnrollment $enrollment): array
    {
        return [
            'provider' => $enrollment->providerKey,
            'id' => $enrollment->id,
            'label' => $enrollment->label,
            'confirmed_at' => $enrollment->confirmedAt?->format(DATE_ATOM),
            'last_used_at' => $enrollment->lastUsedAt?->format(DATE_ATOM),
            'metadata' => $enrollment->metadata,
        ];
    }
}
