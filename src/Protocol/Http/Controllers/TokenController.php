<?php

declare(strict_types=1);

namespace Lock\Server\Protocol\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Lock\Server\Protocol\TokenEndpoint;
use Lock\Server\Protocol\TokenResponse;

class TokenController
{
    public function __construct(protected TokenEndpoint $endpoint) {}

    /**
     * Issue OAuth tokens.
     *
     * Send an application/x-www-form-urlencoded POST with `grant_type` and the
     * credentials required by the client's registered authentication method:
     * HTTP Basic for `client_secret_basic`, body `client_id` and `client_secret`
     * for `client_secret_post`, or `client_id` alone for `none`.
     *
     * The built-in grants accept:
     * - `authorization_code`: required `code` and PKCE `code_verifier`; also
     *   `redirect_uri` when supplied during authorization. Optional `resource`
     *   can narrow the authorized audiences.
     * - `refresh_token`: required `refresh_token`; optional space-delimited
     *   `scope` and `resource` can narrow the original grant. Refresh tokens rotate.
     * - `client_credentials`: optional space-delimited `scope` and `resource`.
     * - `urn:ietf:params:oauth:grant-type:token-exchange`: required `subject_token`,
     *   `subject_token_type=urn:ietf:params:oauth:token-type:access_token`, and
     *   `audience` or `resource` (equal when both are present). Optional `scope`
     *   and `requested_token_type` are supported; only access tokens may be
     *   requested. Actor tokens are unsupported. The realm must enable exchange,
     *   and the client must be confidential or a trusted first-party client.
     *
     * Success is a 200 JSON token response with `Cache-Control: no-store` and
     * `Pragma: no-cache`. OAuth failures carry `error` and `error_description`;
     * invalid client authentication returns 401, invalid grant requests return
     * 400, and server errors return 500.
     * No browser session is required.
     *
     * @see TokenResponse
     */
    public function __invoke(Request $request): JsonResponse
    {
        return new TokenResponse($this->endpoint->issue($request))->toResponse($request);
    }
}
