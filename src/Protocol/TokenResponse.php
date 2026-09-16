<?php

declare(strict_types=1);

namespace Lock\Server\Protocol;

use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\JsonResponse;
use Lock\Server\Shared\Tokens\TokenSet;

/**
 * RFC 6749 §5.1 successful token response. `scope` is sent whenever the
 * token carries one: the granted set may have been narrowed from the request
 * (§3.3), and §5.1 requires it whenever the two differ.
 */
final readonly class TokenResponse implements Responsable
{
    public function __construct(private TokenSet $tokens) {}

    /**
     * Return the OAuth token response as JSON.
     *
     * The 200 response includes string `access_token`, `token_type=Bearer` and
     * integer `expires_in` in seconds. `scope` is a space-delimited string when
     * non-empty; `refresh_token` and `id_token` appear only when issued. Grant
     * extensions may add fields, such as `issued_token_type` for token exchange.
     * Responses carry `Cache-Control: no-store` and `Pragma: no-cache`.
     */
    public function toResponse($request): JsonResponse
    {
        $body = [
            'token_type' => 'Bearer',
            'expires_in' => $this->tokens->accessToken->lifetime(),
            'access_token' => $this->tokens->accessToken->jwt,
        ];

        if ($this->tokens->accessToken->scopes !== []) {
            $body['scope'] = implode(' ', $this->tokens->accessToken->scopes);
        }

        if ($this->tokens->refreshToken !== null) {
            $body['refresh_token'] = $this->tokens->refreshToken;
        }

        if ($this->tokens->idToken !== null) {
            $body['id_token'] = $this->tokens->idToken;
        }

        return new JsonResponse([...$body, ...$this->tokens->extra], 200, [
            'Cache-Control' => 'no-store',
            'Pragma' => 'no-cache',
        ]);
    }
}
