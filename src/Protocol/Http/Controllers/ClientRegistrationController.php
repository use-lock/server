<?php

declare(strict_types=1);

namespace Lock\Server\Protocol\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Date;
use Lock\Server\Shared\Clients\ClientRegistrationException;
use Lock\Server\Shared\Clients\RegisterClient;
use Lock\Server\Shared\Realms\RealmResolver;

/**
 * RFC 7591 dynamic client registration endpoint. The response echoes every
 * registered metadata value (§3.2.1); a confidential client's response also
 * carries `client_secret` with `client_secret_expires_at` 0 (never).
 */
class ClientRegistrationController
{
    /**
     * Register an OAuth client dynamically.
     *
     * Send a JSON object with a non-empty `redirect_uris` array. The default
     * registration handler also accepts `client_name`, `post_logout_redirect_uris`,
     * `grant_types`, `response_types`, `token_endpoint_auth_method`,
     * `backchannel_logout_uri` and `backchannel_logout_session_required`.
     * It supports authorization code clients with optional refresh tokens;
     * `response_types` is `["code"]`. Authentication defaults to `none`; selecting
     * `client_secret_basic` or `client_secret_post` issues a client secret.
     *
     * Success is 201 JSON with `client_id`, `client_id_issued_at` and registered
     * metadata, plus `client_secret` and `client_secret_expires_at=0` when issued.
     * Registration errors return 400 JSON with `error` and `error_description`.
     * The endpoint requires no existing client credentials and returns 404 when
     * dynamic registration is disabled for the realm.
     *
     * @see RegisterClient
     */
    public function __invoke(Request $request, RegisterClient $register, RealmResolver $realms): JsonResponse
    {
        abort_unless($realms->current()->clients()->dynamicRegistration, 404);

        try {
            $registration = $register($request->all());
            $client = $registration->client;
        } catch (ClientRegistrationException $exception) {
            return response()->json([
                'error' => $exception->error,
                'error_description' => $exception->getMessage(),
            ], 400);
        }

        $response = [
            'client_id' => $client->clientId,
            'client_id_issued_at' => Date::now()->getTimestamp(),
        ];

        if ($registration->issuedSecret !== null) {
            $response['client_secret'] = $registration->issuedSecret;
            $response['client_secret_expires_at'] = 0;
        }

        $response += [
            'client_name' => $client->name,
            'redirect_uris' => $client->redirectUris,
            'post_logout_redirect_uris' => $client->postLogoutRedirectUris,
            'grant_types' => $client->grantTypes,
            'response_types' => ['code'],
            'token_endpoint_auth_method' => $client->authMethod->value,
        ];

        if ($client->backchannelLogoutUri !== null) {
            $response['backchannel_logout_uri'] = $client->backchannelLogoutUri;
            $response['backchannel_logout_session_required'] = $client->backchannelLogoutSessionRequired;
        }

        $scopes = $client->assignedScopes();

        // MCP clients send this value back as the authorize `scope`, where `*`
        // is not a scope: a client that may request everything gets no hint.
        if ($scopes !== [] && ! in_array('*', $scopes, true)) {
            $response['scope'] = implode(' ', $scopes);
        }

        return response()->json($response, 201);
    }
}
