<?php

declare(strict_types=1);

namespace Lock\Server\Brokering\Providers;

use DateTimeImmutable;
use Illuminate\Http\Request;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Ecdsa\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token\Builder;
use Lock\Server\Brokering\PendingSocialRedirect;
use Lock\Server\Brokering\TokenResponse;
use Lock\Server\Shared\Brokering\SocialUser;

/**
 * Sign in with Apple deviates from stock OIDC in three ways: the client secret
 * is a self-signed ES256 JWT, the callback arrives as a form_post POST, and
 * the user's name is only delivered once, on first consent, via the `user`
 * request parameter.
 */
class AppleProvider extends GenericOidcProvider
{
    protected function issuer(): string
    {
        return 'https://appleid.apple.com';
    }

    protected function usesPkce(): bool
    {
        return false;
    }

    protected function authorizationEndpoint(): string
    {
        return 'https://appleid.apple.com/auth/authorize';
    }

    protected function tokenEndpoint(): string
    {
        return 'https://appleid.apple.com/auth/token';
    }

    /**
     * @return list<string>
     */
    protected function defaultScopes(): array
    {
        return ['name', 'email'];
    }

    /**
     * @return array<string, string>
     */
    protected function authorizationParameters(PendingSocialRedirect $pending): array
    {
        // Apple requires form_post whenever name/email scopes are requested.
        return parent::authorizationParameters($pending) + ['response_mode' => 'form_post'];
    }

    protected function clientSecret(): string
    {
        $now = new DateTimeImmutable;

        return new Builder(new JoseEncoder, ChainedFormatter::default())
            ->withHeader('kid', (string) $this->config['key_id'])
            ->issuedBy((string) $this->config['team_id'])
            ->relatedTo((string) $this->config['client_id'])
            ->permittedFor('https://appleid.apple.com')
            ->issuedAt($now)
            ->expiresAt($now->modify('+5 minutes'))
            ->getToken(new Sha256, InMemory::plainText($this->privateKey()))
            ->toString();
    }

    protected function fetchUser(TokenResponse $tokens, PendingSocialRedirect $pending, Request $request): SocialUser
    {
        $user = parent::fetchUser($tokens, $pending, $request);

        // On first consent Apple sends the name out-of-band as a JSON `user`
        // request parameter; it never appears in the id_token.
        $firstConsent = json_decode((string) $request->input('user', ''), true);

        if (is_array($firstConsent)) {
            $name = trim(implode(' ', array_filter([
                $firstConsent['name']['firstName'] ?? null,
                $firstConsent['name']['lastName'] ?? null,
            ], is_string(...))));

            if ($name !== '') {
                return new SocialUser(
                    id: $user->id,
                    email: $user->email,
                    emailVerified: $user->emailVerified,
                    name: $name,
                    nickname: $user->nickname,
                    avatar: $user->avatar,
                    raw: $user->raw + ['user' => $firstConsent],
                    accessToken: $user->accessToken,
                    refreshToken: $user->refreshToken,
                    expiresIn: $user->expiresIn,
                    idToken: $user->idToken,
                );
            }
        }

        return $user;
    }

    private function privateKey(): string
    {
        return str_replace('\n', "\n", (string) $this->config['private_key']);
    }
}
