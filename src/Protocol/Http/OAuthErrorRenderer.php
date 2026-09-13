<?php

declare(strict_types=1);

namespace Lock\Server\Protocol\Http;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Route;
use Lock\Server\Protocol\EndpointUrl;
use Lock\Server\Shared\Protocol\OAuthServerException;
use Lock\Server\Shared\Realms\IssuerResolver;
use Lock\Server\Shared\Realms\RealmResolver;
use Symfony\Component\HttpFoundation\Response as SymfonyResponse;

final readonly class OAuthErrorRenderer
{
    public function __construct(
        private IssuerResolver $issuer,
        private RealmResolver $realms,
        private EndpointUrl $endpoints,
    ) {}

    public function render(OAuthServerException $exception): SymfonyResponse
    {
        if ($exception->redirectUri !== null) {
            return new RedirectResponse($this->appendQuery($exception->redirectUri, array_filter([
                'error' => $exception->error,
                'error_description' => $exception->description,
                'state' => $exception->state,
                'iss' => $this->issuer->url(),
            ], fn (?string $value): bool => $value !== null)));
        }

        $status = match ($exception->error) {
            null, 'invalid_client', 'invalid_token', 'login_required', 'interaction_required', 'consent_required' => 401,
            'insufficient_scope' => 403,
            'server_error' => 500,
            default => 400,
        };

        $headers = ['Cache-Control' => 'no-store', 'Pragma' => 'no-cache'];
        $challenge = match ($exception->error) {
            'invalid_client' => 'Basic realm="'.$this->realms->current()->identifier().'"',
            null, 'invalid_token', 'insufficient_scope' => $this->bearerChallenge($exception->error),
            default => null,
        };

        if ($challenge !== null) {
            $headers['WWW-Authenticate'] = $challenge;
        }

        return $exception->error === null
            ? new Response('', $status, $headers)
            : new JsonResponse(['error' => $exception->error, 'error_description' => $exception->description], $status, $headers);
    }

    /** RFC 6750 §3.1 distinguishes missing credentials from rejected credentials. */
    public function renderAuthentication(AuthenticationException $exception, Request $request): ?SymfonyResponse
    {
        $apiGuard = (string) config('oidc.auth.api_guard', 'oidc');
        $usesBearer = array_any($exception->guards(), function (?string $guard) use ($apiGuard): bool {
            $guard ??= (string) config('auth.defaults.guard');

            return $guard === $apiGuard || config("auth.guards.{$guard}.driver") === 'oidc';
        });

        if (! $usesBearer) {
            return null;
        }

        return $this->render($request->bearerToken() === null
            ? OAuthServerException::bearerRequired()
            : OAuthServerException::invalidToken());
    }

    /** RFC 9728 §5.1 advertises metadata only when its endpoint is registered. */
    private function bearerChallenge(?string $error): string
    {
        $parameters = array_filter([
            'realm' => $this->realms->current()->identifier(),
            'error' => $error,
            'resource_metadata' => Route::has('oidc.protected-resource') ? $this->endpoints->of('oidc.protected-resource') : null,
        ], fn (?string $value): bool => $value !== null);

        return 'Bearer '.implode(', ', array_map(
            fn (string $name, string $value): string => $name.'="'.$value.'"',
            array_keys($parameters),
            $parameters,
        ));
    }

    /** @param array<string, string> $parameters */
    private function appendQuery(string $uri, array $parameters): string
    {
        return $uri.(str_contains($uri, '?') ? '&' : '?').http_build_query($parameters, '', '&', PHP_QUERY_RFC3986);
    }
}
