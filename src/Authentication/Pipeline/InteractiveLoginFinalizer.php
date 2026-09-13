<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\Pipeline;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Lock\Server\Authentication\Concerns\ResolvesIdentityGuard;
use Lock\Server\Authentication\Context\LoginState;
use Lock\Server\Authentication\Contracts\DeviceRecognizer;
use Lock\Server\Authentication\Contracts\LoginFinalizer;
use Lock\Server\Authentication\Contracts\SecondFactorGate;
use Lock\Server\Authentication\Events\LoginFailed;
use Lock\Server\Authentication\Events\LoginSucceeded;
use Lock\Server\Authentication\LoginOutcome;
use Lock\Server\Authentication\RequiredActions\PendingRequiredActions;
use Lock\Server\Authentication\RequiredActions\RequiredActionRegistry;
use Lock\Server\Shared\Authentication\PendingActions;
use Lock\Server\Shared\Authentication\PendingAuthorization;
use Lock\Server\Shared\Clients\Client;
use Lock\Server\Shared\Clients\Clients;
use Lock\Server\Shared\Realms\RealmResolver;
use Lock\Server\Shared\Realms\Settings\MfaRequirement;

/**
 * The single post-authentication sequence for interactive logins: postLogin
 * policy, claim buffering, second-factor gating, guard login. Every path that
 * authenticates a user interactively (password, social, registration,
 * password reset, passkey) must finalize through here — a path that calls
 * guard->login() directly bypasses the policy and leaves amr untracked.
 */
final readonly class InteractiveLoginFinalizer implements LoginFinalizer
{
    use ResolvesIdentityGuard;

    public function __construct(
        private SecondFactorGate $secondFactor,
        private LoginState $sessionState,
        private PostLoginPipeline $pipeline,
        private DeviceRecognizer $deviceRecognizer,
        private PendingAuthorization $pending,
        private Clients $clients,
        private PendingActions $actions,
        private RequiredActionRegistry $registry,
        private RealmResolver $realms,
    ) {}

    private function pendingClient(Request $request): ?Client
    {
        $clientId = $this->pending->clientId($request);

        return $clientId === null ? null : $this->clients->findActive($clientId);
    }

    /**
     * $challengeEnrolledFactors controls whether an enrolled second factor is
     * challenged automatically. Passkey logins pass false — the ceremony
     * already verified user presence on a bound device — but an explicit
     * requireMfa() from the pipeline still forces the challenge.
     */
    public function finalize(
        Request $request,
        Authenticatable $user,
        string $method,
        bool $remember = false,
        bool $challengeEnrolledFactors = true,
    ): LoginOutcome {
        $this->sessionState->start($method);

        $api = $this->pipeline->run(new LoginEvent(
            user: $user,
            client: $this->pendingClient($request),
            scopes: $this->pending->scopes($request),
            requestedAcrValues: $this->pending->acrValues($request),
            ip: $request->ip(),
            userAgent: $request->userAgent(),
            amr: [$method],
            authTime: null,
            recognizer: $this->deviceRecognizer,
            request: $request,
        ));

        if ($api->isDenied()) {
            Log::warning('oidc: login denied by postLogin', ['method' => $method, 'reason' => $api->denyReason()]);
            event(new LoginFailed(
                method: $method,
                reason: 'policy_denied',
                userId: (string) $user->getAuthIdentifier(),
                denyReason: $api->denyReason(),
            ));
            $this->sessionState->forget();

            return LoginOutcome::Denied;
        }

        $this->sessionState->putClaims($api->idTokenClaims(), $api->accessTokenClaims());

        $mfa = $this->realms->current()->authentication()->mfa;
        $forced = $api->mfaRequired() || $mfa === MfaRequirement::Always;
        $challengeable = $mfa !== MfaRequirement::Never && $this->secondFactor->hasChallengeableFactors($user);
        $actions = $this->knownActions($api->requiredActions());

        if ($challengeable && ($challengeEnrolledFactors || $forced)) {
            $this->sessionState->putRequestedActions($actions);
            $this->secondFactor->beginChallenge($user, $remember);

            return LoginOutcome::MfaChallenge;
        }

        // A realm that requires a factor the user does not have enrolls one.
        // With nothing to enroll — no provider, or the realm switched second
        // factors off — the demand cannot be met, and the login fails closed
        // rather than looping on a screen with no options.
        if ($forced && ! $challengeable) {
            if ($mfa === MfaRequirement::Never || ! $this->secondFactor->canEnrollFactor($user)) {
                Log::warning('oidc: login denied, MFA required but no factor can satisfy it', ['method' => $method]);
                event(new LoginFailed(
                    method: $method,
                    reason: 'mfa_required_without_factor',
                    userId: (string) $user->getAuthIdentifier(),
                ));
                $this->sessionState->forget();

                return LoginOutcome::Denied;
            }

            $actions[] = 'configure_mfa';
        }

        $this->sessionState->putRequestedActions($actions);

        return $this->finish($request, $user, $remember);
    }

    public function finish(Request $request, Authenticatable $user, bool $remember = false): LoginOutcome
    {
        if ($this->actions->for($user) !== []) {
            new PendingRequiredActions($user->getAuthIdentifier(), $remember)->store();

            return LoginOutcome::RequiredAction;
        }

        PendingRequiredActions::forget();
        $this->complete($request, $user, $remember);

        return LoginOutcome::LoggedIn;
    }

    /**
     * An action the pipeline names but nobody registered would park the login
     * on a screen that does not exist, so it is dropped and reported instead.
     *
     * @param  list<string>  $keys
     * @return list<string>
     */
    private function knownActions(array $keys): array
    {
        return array_values(array_filter($keys, function (string $key): bool {
            if ($this->registry->has($key)) {
                return true;
            }

            Log::warning("oidc: postLogin required an unregistered action [{$key}]");

            return false;
        }));
    }

    public function complete(Request $request, Authenticatable $user, bool $remember = false): void
    {
        // The guard already regenerated the session on login; doing it again
        // would detach the OIDC session from the browser session it recorded.
        $this->sessionGuard()->login($user, $remember);

        event(new LoginSucceeded((string) $user->getAuthIdentifier(), $this->sessionState->amr(), $remember));
    }
}
