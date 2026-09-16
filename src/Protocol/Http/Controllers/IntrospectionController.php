<?php

declare(strict_types=1);

namespace Lock\Server\Protocol\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Lock\Server\Protocol\Clients\ClientAuthenticator;
use Lock\Server\Shared\Protocol\OAuthServerException;
use Lock\Server\Shared\Tokens\PresentedTokens;

class IntrospectionController
{
    public function __construct(private readonly PresentedTokens $tokens) {}

    /**
     * Inspect an access token or refresh token.
     *
     * Send an application/x-www-form-urlencoded POST with required `token` and
     * optional `token_type_hint`. Authenticate a confidential client using its
     * registered `client_secret_basic` or `client_secret_post` method.
     *
     * A 200 JSON response contains `active` and, for an active token visible to
     * the caller, token metadata. An inactive or undisclosed token returns only
     * `active: false`. Missing input returns a 400 OAuth error; failed client
     * authentication returns 401. No browser session is required.
     */
    public function __invoke(Request $request, ClientAuthenticator $clients): JsonResponse
    {
        $client = $clients->authenticate($request);

        if (! $client->confidential) {
            throw OAuthServerException::invalidClient('Only confidential clients may introspect tokens.');
        }

        $value = $request->input('token');

        if (! is_string($value) || $value === '') {
            throw OAuthServerException::invalidRequest('The token parameter is missing.');
        }

        $hint = $request->input('token_type_hint');

        return response()->json($this->tokens->introspect($client, $value, is_string($hint) ? $hint : null));
    }
}
