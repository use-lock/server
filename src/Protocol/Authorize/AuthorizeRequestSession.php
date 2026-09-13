<?php

declare(strict_types=1);

namespace Lock\Server\Protocol\Authorize;

use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Lock\Server\Protocol\Exceptions\InvalidConsentTokenException;
use Lock\Server\Shared\Protocol\AuthorizeRequest;
use RuntimeException;

/**
 * The consent form must return its auth token to prevent approving
 * somebody else's pending authorization.
 */
final class AuthorizeRequestSession
{
    private const string ACR_VALUES_KEY = 'oidc.requested_acr_values';

    private const string TOKEN_KEY = 'oidc.consent_token';

    private const string REQUEST_KEY = 'oidc.authorize_request';

    public function remember(Request $request, AuthorizeRequest $authorizeRequest): void
    {
        $request->session()->forget(self::TOKEN_KEY);
        $request->session()->put(self::REQUEST_KEY, serialize($authorizeRequest));
        $this->rememberAcrValues($request, $authorizeRequest->acrValues);
    }

    public function forget(Request $request): void
    {
        $request->session()->forget([self::TOKEN_KEY, self::REQUEST_KEY, self::ACR_VALUES_KEY]);
    }

    public function intendedUrl(Request $request, AuthorizeRequest $authorizeRequest): string
    {
        $parameters = $request->isMethod('POST') ? $request->request->all() : $request->query->all();
        $parameters = array_intersect_key($parameters, array_flip([
            'client_id', 'redirect_uri', 'response_type', 'response_mode', 'scope', 'state',
            'code_challenge', 'code_challenge_method', 'nonce', 'prompt', 'max_age',
            'acr_values', 'id_token_hint',
        ]));

        if ($authorizeRequest->resources !== []) {
            $parameters['resource'] = $authorizeRequest->resources;
        }

        return $request->url().'?'.http_build_query($parameters);
    }

    /** @return string the auth token the consent form must echo back */
    public function stash(Request $request, AuthorizeRequest $authorizeRequest): string
    {
        $token = Str::random();

        $request->session()->put(self::TOKEN_KEY, $token);
        $request->session()->put(self::REQUEST_KEY, serialize($authorizeRequest));

        return $token;
    }

    public function pull(Request $request): AuthorizeRequest
    {
        if ($request->isNotFilled('auth_token')
            || $request->session()->pull(self::TOKEN_KEY) !== $request->input('auth_token')) {
            $request->session()->forget([self::TOKEN_KEY, self::REQUEST_KEY]);

            throw InvalidConsentTokenException::different();
        }

        $serialized = $request->session()->pull(self::REQUEST_KEY);

        return $this->restore($serialized)
            ?? throw new RuntimeException('Authorization request was not present in the session.');
    }

    public function peek(Request $request): ?AuthorizeRequest
    {
        return $this->restore($request->session()->get(self::REQUEST_KEY));
    }

    /** @param list<string> $values */
    public function rememberAcrValues(Request $request, array $values): void
    {
        if ($values === []) {
            $request->session()->forget(self::ACR_VALUES_KEY);

            return;
        }

        $request->session()->put(self::ACR_VALUES_KEY, $values);
    }

    /** @return list<string> */
    public function acrValues(Request $request): array
    {
        $values = $request->session()->get(self::ACR_VALUES_KEY, []);

        return is_array($values) ? array_values(array_filter($values, is_string(...))) : [];
    }

    private function restore(mixed $serialized): ?AuthorizeRequest
    {
        if (! is_string($serialized)) {
            return null;
        }

        $authorizeRequest = unserialize($serialized, ['allowed_classes' => [AuthorizeRequest::class]]);

        return $authorizeRequest instanceof AuthorizeRequest ? $authorizeRequest : null;
    }
}
