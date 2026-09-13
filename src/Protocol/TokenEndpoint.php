<?php

declare(strict_types=1);

namespace Lock\Server\Protocol;

use Illuminate\Http\Request;
use Lock\Server\Protocol\Clients\ClientAuthenticator;
use Lock\Server\Shared\Protocol\OAuthServerException;
use Lock\Server\Shared\Realms\RealmResolver;
use Lock\Server\Shared\Tokens\Grant;
use Lock\Server\Shared\Tokens\GrantRequest;
use Lock\Server\Shared\Tokens\TokenSet;

/**
 * RFC 6749 §3.2: authenticate the client before invoking its grant.
 */
final readonly class TokenEndpoint
{
    /** @param  list<Grant>  $grants */
    public function __construct(
        private ClientAuthenticator $clients,
        private array $grants,
        private RealmResolver $realms,
    ) {}

    public function issue(Request $request): TokenSet
    {
        $grantType = $request->input('grant_type');

        if (! is_string($grantType) || $grantType === '') {
            throw OAuthServerException::invalidRequest('The grant_type parameter is missing.');
        }

        if ($grantType === 'urn:ietf:params:oauth:grant-type:token-exchange' && ! $this->realms->current()->clients()->tokenExchange) {
            throw OAuthServerException::unsupportedGrantType();
        }

        $grant = $this->grant($grantType) ?? throw OAuthServerException::unsupportedGrantType();

        $client = $this->clients->authenticate($request, $grant->type());

        return $grant->handle($client, new GrantRequest($request->all(), $request->path(), $request->request->all()));
    }

    private function grant(string $type): ?Grant
    {
        foreach ($this->grants as $grant) {
            if ($grant->type() === $type) {
                return $grant;
            }
        }

        return null;
    }
}
