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
