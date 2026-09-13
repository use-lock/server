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
