<?php

declare(strict_types=1);

namespace Lock\Server\Protocol\Authorize;

use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Facades\DB;
use Lock\Server\Protocol\Http\OAuthErrorRenderer;
use Lock\Server\Shared\Authentication\LoginContext;
use Lock\Server\Shared\Clients\Client;
use Lock\Server\Shared\Protocol\AuthorizeRequest;
use Lock\Server\Shared\Protocol\OAuthServerException;
use Lock\Server\Shared\Realms\IssuerResolver;
use Lock\Server\Shared\Sessions\Sessions;
use Lock\Server\Shared\Tokens\AuthorizationCodes;
use Symfony\Component\HttpFoundation\Response;

/**
 * OAuth 2.1 §4.1.2 code redirect with the RFC 9207 §2 `iss` parameter.
 */
final readonly class AuthorizationCodeIssuer
{
    public function __construct(
        private AuthorizationCodes $codes,
        private Sessions $sessions,
        private LoginContext $loginContext,
        private OAuthErrorRenderer $errors,
        private IssuerResolver $issuer,
    ) {}

    public function approve(AuthorizeRequest $request, Client $client): RedirectResponse
    {
        $code = DB::transaction(function () use ($request, $client): string {
            $session = $this->sessions->current();
            $code = $this->codes->issue($request, $client, $session, $this->loginContext->snapshot());

            if ($session->sid !== null) {
                $this->sessions->recordParticipant($session->sid, $client->key);
            }

            return $code;
        });

        return new RedirectResponse($this->appendQuery($request->redirectUri, array_filter([
            'code' => $code,
            'state' => $request->state,
            'iss' => $this->issuer->url(),
        ], fn (?string $value): bool => $value !== null)));
    }

    /** @param  array<string, string>  $parameters */
    private function appendQuery(string $uri, array $parameters): string
    {
        return $uri.(str_contains($uri, '?') ? '&' : '?').http_build_query($parameters, '', '&', PHP_QUERY_RFC3986);
    }

    public function deny(AuthorizeRequest $request): Response
    {
        return $this->errors->render(OAuthServerException::accessDenied('The user denied the request.', $request->redirectUri, $request->state));
    }
}
