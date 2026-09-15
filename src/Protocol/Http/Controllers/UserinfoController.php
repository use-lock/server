<?php

declare(strict_types=1);

namespace Lock\Server\Protocol\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Lock\Server\Shared\Protocol\OAuthServerException;
use Lock\Server\Shared\Protocol\ProtocolClaims;
use Lock\Server\Shared\Scopes\ClaimsAudience;
use Lock\Server\Shared\Scopes\ClaimsRequest;
use Lock\Server\Shared\Scopes\ClaimsResolver;
use Lock\Server\Shared\Tokens\AccessTokenBearer;

/**
 * OpenID Connect Core §5.3. The `sub` is the provider's and must match the
 * id_token's (§5.3.2), so a resolver cannot replace it or any other
 * protocol claim.
 */
class UserinfoController
{
    /**
     * Read claims for the authenticated end user.
     *
     * GET and POST require an Authorization bearer access token associated with
     * an end user and granting the `openid` scope. Client-credentials tokens do
     * not identify an end user. A browser session does not replace the token.
     *
     * Success is 200 JSON with required string `sub` and additional claims
     * resolved from the granted scopes. Missing credentials produce a bearer
     * challenge with HTTP 401 and an empty body. Invalid tokens return 401 with
     * `error=invalid_token`; missing `openid` scope returns 403 with
     * `error=insufficient_scope`. The response's `sub` must match the ID token.
     */
    public function __invoke(Request $request, ClaimsResolver $claims): JsonResponse
    {
        $user = Auth::guard((string) config('oidc.auth.api_guard', 'oidc'))->user();

        if (! $user instanceof AccessTokenBearer || $user->currentAccessToken()?->userId() === null) {
            throw $request->bearerToken() === null
                ? OAuthServerException::bearerRequired()
                : OAuthServerException::invalidToken();
        }

        $token = $user->currentAccessToken();
        $scopes = $token->scopes();

        if (! in_array('openid', $scopes, true)) {
            throw OAuthServerException::insufficientScope();
        }

        $resolved = $claims->resolve(new ClaimsRequest(
            user: $user,
            audience: ClaimsAudience::Userinfo,
            clientId: $token->clientId(),
            scopes: $scopes,
        ));

        return response()->json([
            'sub' => (string) $user->getAuthIdentifier(),
            ...array_filter($resolved, fn (string $name): bool => ! ProtocolClaims::isReserved($name), ARRAY_FILTER_USE_KEY),
        ]);
    }
}
