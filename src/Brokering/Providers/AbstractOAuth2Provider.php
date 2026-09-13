<?php

declare(strict_types=1);

namespace Lock\Server\Brokering\Providers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use Lock\Server\Brokering\PendingSocialRedirect;
use Lock\Server\Brokering\TokenResponse;
use Lock\Server\Shared\Brokering\InvalidStateException;
use Lock\Server\Shared\Brokering\SocialAuthenticationException;
use Lock\Server\Shared\Brokering\SocialCallback;
use Lock\Server\Shared\Brokering\SocialProvider;
use Lock\Server\Shared\Brokering\SocialUser;
use Symfony\Component\HttpFoundation\Response;

abstract class AbstractOAuth2Provider implements SocialProvider
{
    /**
     * @param  array<string, mixed>  $config
     */
    public function __construct(
        protected readonly string $key,
        protected readonly array $config,
    ) {}

    public function key(): string
    {
        return $this->key;
    }

    abstract protected function authorizationEndpoint(): string;

    abstract protected function tokenEndpoint(): string;

    /**
     * @return list<string>
     */
    abstract protected function defaultScopes(): array;

    abstract protected function fetchUser(TokenResponse $tokens, PendingSocialRedirect $pending, Request $request): SocialUser;

    public function redirect(Request $request, string $intent = SocialProvider::INTENT_LOGIN): Response
    {
        $pending = new PendingSocialRedirect(
            provider: $this->key,
            intent: $intent,
            state: Str::random(40),
            codeVerifier: $this->usesPkce() ? Str::random(64) : null,
            nonce: $this->usesNonce() ? Str::random(40) : null,
        );

        $pending->store($request);

        return redirect()->away(
            $this->authorizationEndpoint().'?'.http_build_query($this->authorizationParameters($pending)),
        );
    }

    public function callback(Request $request): SocialCallback
    {
        $pending = PendingSocialRedirect::pull($request);

        if (! $pending instanceof PendingSocialRedirect) {
            throw new InvalidStateException('The social callback has no pending authorization.');
        }

        return new SocialCallback($pending->intent, $this->user($request, $pending));
    }

    public function user(Request $request, PendingSocialRedirect $pending): SocialUser
    {
        $state = $request->input('state');
        $state = is_string($state) ? $state : '';

        if ($pending->provider !== $this->key || $state === '' || ! hash_equals($pending->state, $state)) {
            throw new InvalidStateException('The social callback state does not match the pending authorization.');
        }

        $code = $request->input('code');
        $code = is_string($code) ? $code : '';

        if ($code === '') {
            throw new SocialAuthenticationException('The social callback is missing the authorization code.');
        }

        return $this->fetchUser($this->exchangeCode($code, $pending->codeVerifier), $pending, $request);
    }

    protected function usesPkce(): bool
    {
        return true;
    }

    protected function usesNonce(): bool
    {
        return false;
    }

    /**
     * @return array<string, string>
     */
    protected function authorizationParameters(PendingSocialRedirect $pending): array
    {
        $params = [
            'client_id' => (string) $this->config['client_id'],
            'redirect_uri' => $this->redirectUrl(),
            'response_type' => 'code',
            'scope' => implode(' ', $this->defaultScopes()),
            'state' => $pending->state,
        ];

        if ($pending->codeVerifier !== null) {
            $params['code_challenge'] = sodium_bin2base64(hash('sha256', $pending->codeVerifier, true), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
            $params['code_challenge_method'] = 'S256';
        }

        if ($pending->nonce !== null) {
            $params['nonce'] = $pending->nonce;
        }

        return $params;
    }

    protected function exchangeCode(string $code, ?string $codeVerifier): TokenResponse
    {
        $response = Http::asForm()->acceptJson()->post($this->tokenEndpoint(), array_filter([
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $this->redirectUrl(),
            'client_id' => (string) $this->config['client_id'],
            'client_secret' => $this->clientSecret(),
            'code_verifier' => $codeVerifier,
        ], static fn (?string $value): bool => $value !== null && $value !== ''));

        if ($response->failed()) {
            throw new SocialAuthenticationException("The [{$this->key}] token endpoint responded with HTTP {$response->status()}.");
        }

        return TokenResponse::fromArray((array) $response->json());
    }

    protected function clientSecret(): ?string
    {
        $secret = $this->config['client_secret'] ?? null;

        return is_string($secret) && $secret !== '' ? $secret : null;
    }

    protected function redirectUrl(): string
    {
        return route('identity.social.callback', ['provider' => $this->key]);
    }
}
