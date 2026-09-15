<?php

declare(strict_types=1);

namespace Lock\Server\Protocol\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Lock\Server\Protocol\Clients\ClientAuthenticator;
use Lock\Server\Shared\Protocol\OAuthServerException;
use Lock\Server\Shared\Tokens\PresentedTokens;

class RevocationController
{
    public function __construct(private readonly PresentedTokens $tokens) {}

    /**
     * Revoke an access token or refresh token.
     *
     * Send an application/x-www-form-urlencoded POST with required `token` and
     * optional `token_type_hint`. Use the client's registered authentication
     * method: `client_secret_basic`, `client_secret_post` or `none`.
     *
     * Success is HTTP 200 with an empty body, including when the token is unknown
     * or cannot be revoked by this client. Missing input and failed client
     * authentication return 400 and 401 OAuth errors respectively. No browser
     * session is required.
     */
    public function __invoke(Request $request, ClientAuthenticator $clients): Response
    {
        $client = $clients->authenticate($request);
        $value = $request->input('token');

        if (! is_string($value) || $value === '') {
            throw OAuthServerException::invalidRequest('The token parameter is missing.');
        }

        $hint = $request->input('token_type_hint');
        $this->tokens->revoke($client, $value, is_string($hint) ? $hint : null);

        return response()->noContent(200);
    }
}
