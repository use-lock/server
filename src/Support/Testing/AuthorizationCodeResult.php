<?php

declare(strict_types=1);

namespace Lock\Server\Support\Testing;

use Illuminate\Testing\TestResponse;
use Symfony\Component\HttpFoundation\Response;

/**
 * The outcome of {@see InteractsWithOidc::authorizeAndApprove()}. The token
 * fields are null when the token endpoint returned an error — assert on
 * `$response` in that case.
 */
final readonly class AuthorizationCodeResult
{
    /**
     * @param  TestResponse<Response>  $response
     */
    public function __construct(
        public TestResponse $response,
        public ?string $accessToken,
        public ?string $idToken,
        public ?string $refreshToken,
    ) {}

    /**
     * Must never throw, even on a non-JSON body — the token leg is returned
     * unasserted and callers assert on `$response` themselves.
     *
     * @param  TestResponse<Response>  $response
     */
    public static function fromResponse(TestResponse $response): self
    {
        $decoded = json_decode($response->getContent(), true);
        $isJsonObject = is_array($decoded);

        return new self(
            $response,
            $isJsonObject ? $response->json('access_token') : null,
            $isJsonObject ? $response->json('id_token') : null,
            $isJsonObject ? $response->json('refresh_token') : null,
        );
    }
}
