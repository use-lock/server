<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Protocol;

/**
 * A validated OAuth 2.1 §4.1.1 / OpenID Connect Core §3.1.2.1 authorization
 * request. Scalar only, so it survives the consent round trip in the session.
 */
final class AuthorizeRequest
{
    /**
     * @param  string  $clientId  the wire client_id
     * @param  string  $redirectUri  the URI the response goes to, resolved against the registration
     * @param  bool  $redirectUriRequested  whether the client sent one; if so the token request must repeat it
     * @param  list<string>  $scopes  the requested scopes plus the client's default scopes
     * @param  list<string>  $prompt  the validated prompt values, in request order
     * @param  int|null  $maxAge  seconds since authentication the client tolerates
     * @param  list<string>  $acrValues
     * @param  string|null  $idTokenHintSubject  the sub of a verified id_token_hint
     * @param  list<string>  $resources  RFC 8707 resources the token is requested for; empty for the realm default
     */
    public function __construct(
        public readonly string $clientId,
        public readonly string $redirectUri,
        public readonly bool $redirectUriRequested,
        public readonly array $scopes,
        public readonly ?string $state,
        public readonly string $codeChallenge,
        public readonly string $codeChallengeMethod,
        public readonly ?string $nonce,
        public readonly array $prompt = [],
        public readonly ?int $maxAge = null,
        public readonly array $acrValues = [],
        public readonly ?string $idTokenHintSubject = null,
        public readonly array $resources = [],
        public ?string $userId = null,
    ) {}
}
