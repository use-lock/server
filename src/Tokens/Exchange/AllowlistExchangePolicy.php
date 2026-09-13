<?php

declare(strict_types=1);

namespace Lock\Server\Tokens\Exchange;

use Lock\Server\Shared\Protocol\OAuthServerException;
use Lock\Server\Tokens\Contracts\ExchangePolicy;

class AllowlistExchangePolicy implements ExchangePolicy
{
    public function authorize(ExchangeRequest $request): ExchangeGrantResult
    {
        $claims = $request->subjectClaims;
        $subject = (string) ($claims['sub'] ?? '');
        if ($subject === '') {
            throw OAuthServerException::invalidGrant('The subject token has no subject.');
        }

        $subjectAudience = $this->normalize($claims['aud'] ?? []);
        $subjectClientId = is_string($claims['client_id'] ?? null) ? $claims['client_id'] : null;
        $clientId = $request->client->clientId;

        if (! in_array($clientId, $subjectAudience, true) && $subjectClientId !== $clientId) {
            throw OAuthServerException::accessDenied('The subject token was not issued to the requesting client.');
        }

        $allowed = $request->client->allowedAudiences;
        $audience = $request->requestedAudience;
        if ($audience === null || ! in_array($audience, $allowed, true)) {
            throw OAuthServerException::invalidTarget('The requested audience is not permitted for this client.');
        }

        $subjectScopes = $this->scopeList($claims['scope'] ?? '');
        $requested = $request->requestedScopes ?? $subjectScopes;
        $widened = array_diff($requested, $subjectScopes);
        if ($widened !== []) {
            throw OAuthServerException::invalidScope(implode(' ', $widened));
        }

        return new ExchangeGrantResult(
            userId: $subject,
            scopes: array_values($requested),
            audience: [$audience],
            expiresAt: $request->subjectExpiresAt,
        );
    }

    /** @return string[] */
    private function normalize(mixed $aud): array
    {
        return array_values(array_filter(is_array($aud) ? $aud : [$aud], is_string(...)));
    }

    /** @return string[] */
    private function scopeList(mixed $scope): array
    {
        return is_string($scope) && $scope !== '' ? explode(' ', $scope) : [];
    }
}
