<?php

declare(strict_types=1);

namespace Lock\Server\Sessions\Actions;

use Lock\Server\Sessions\Contracts\SessionTokenProvider;
use Lock\Server\Shared\Clients\Clients;
use Lock\Server\Shared\Tokens\IssuedToken;
use Lock\Server\Shared\Tokens\TokenExchange;
use RuntimeException;

/**
 * Exchange the current user's session root token for an access token scoped
 * to one audience, on behalf of the first-party client (RFC 8693).
 */
readonly class IssueScopedToken
{
    public function __construct(
        protected Clients $clients,
        protected SessionTokenProvider $sessionTokens,
        protected TokenExchange $exchanger,
    ) {}

    /**
     * @param  string[]  $scopes
     */
    public function __invoke(string $audience, array $scopes): IssuedToken
    {
        $subject = $this->sessionTokens->currentToken();

        if ($subject === null) {
            throw new RuntimeException('No session token is available for the current user.');
        }

        $client = $this->clients->firstParty();

        return IssuedToken::fromMinted($this->exchanger->exchange($subject, $client, $audience, $scopes), $audience);
    }
}
