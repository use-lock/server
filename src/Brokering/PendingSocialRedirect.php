<?php

declare(strict_types=1);

namespace Lock\Server\Brokering;

use Illuminate\Http\Request;
use Lock\Server\Shared\Brokering\SocialProvider;

final readonly class PendingSocialRedirect
{
    public const string SESSION_KEY = 'oidc.social.pending';

    public function __construct(
        public string $provider,
        public string $intent,
        public string $state,
        public ?string $codeVerifier,
        public ?string $nonce,
    ) {}

    public function store(Request $request): void
    {
        $request->session()->put(self::SESSION_KEY, [
            'provider' => $this->provider,
            'intent' => $this->intent,
            'state' => $this->state,
            'code_verifier' => $this->codeVerifier,
            'nonce' => $this->nonce,
        ]);
    }

    public static function pull(Request $request): ?self
    {
        $pending = $request->session()->pull(self::SESSION_KEY);

        if (! is_array($pending) || ! is_string($pending['provider'] ?? null) || ! is_string($pending['state'] ?? null)) {
            return null;
        }

        return new self(
            provider: $pending['provider'],
            intent: is_string($pending['intent'] ?? null) ? $pending['intent'] : SocialProvider::INTENT_LOGIN,
            state: $pending['state'],
            codeVerifier: is_string($pending['code_verifier'] ?? null) ? $pending['code_verifier'] : null,
            nonce: is_string($pending['nonce'] ?? null) ? $pending['nonce'] : null,
        );
    }
}
