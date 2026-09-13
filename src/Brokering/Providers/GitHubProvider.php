<?php

declare(strict_types=1);

namespace Lock\Server\Brokering\Providers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Lock\Server\Brokering\PendingSocialRedirect;
use Lock\Server\Brokering\TokenResponse;
use Lock\Server\Shared\Brokering\SocialAuthenticationException;
use Lock\Server\Shared\Brokering\SocialUser;

/**
 * GitHub is plain OAuth2 (no OIDC): identity comes from the REST API, and the
 * verified primary email requires a separate endpoint.
 */
class GitHubProvider extends AbstractOAuth2Provider
{
    protected function usesPkce(): bool
    {
        return false;
    }

    protected function authorizationEndpoint(): string
    {
        return 'https://github.com/login/oauth/authorize';
    }

    protected function tokenEndpoint(): string
    {
        return 'https://github.com/login/oauth/access_token';
    }

    /**
     * @return list<string>
     */
    protected function defaultScopes(): array
    {
        return ['read:user', 'user:email'];
    }

    protected function fetchUser(TokenResponse $tokens, PendingSocialRedirect $pending, Request $request): SocialUser
    {
        if ($tokens->accessToken === null) {
            throw new SocialAuthenticationException('The [github] token response did not include an access_token.');
        }

        $response = Http::withToken($tokens->accessToken)
            ->acceptJson()
            ->get('https://api.github.com/user');

        if ($response->failed()) {
            throw new SocialAuthenticationException("The [github] user endpoint responded with HTTP {$response->status()}.");
        }

        $profile = (array) $response->json();

        [$email, $emailVerified] = $this->primaryVerifiedEmail($tokens->accessToken);

        return new SocialUser(
            id: (string) $profile['id'],
            email: $email,
            emailVerified: $emailVerified,
            name: is_string($profile['name'] ?? null) ? $profile['name'] : null,
            nickname: is_string($profile['login'] ?? null) ? $profile['login'] : null,
            avatar: is_string($profile['avatar_url'] ?? null) ? $profile['avatar_url'] : null,
            raw: $profile,
            accessToken: $tokens->accessToken,
            refreshToken: $tokens->refreshToken,
            expiresIn: $tokens->expiresIn,
        );
    }

    /**
     * @return array{0: string|null, 1: bool}
     */
    private function primaryVerifiedEmail(string $accessToken): array
    {
        $emails = Http::withToken($accessToken)
            ->acceptJson()
            ->get('https://api.github.com/user/emails');

        if ($emails->failed()) {
            return [null, false];
        }

        foreach ((array) $emails->json() as $entry) {
            if (is_array($entry) && ($entry['primary'] ?? false) && ($entry['verified'] ?? false) && is_string($entry['email'] ?? null)) {
                return [$entry['email'], true];
            }
        }

        return [null, false];
    }
}
