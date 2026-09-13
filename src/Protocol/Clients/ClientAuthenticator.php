<?php

declare(strict_types=1);

namespace Lock\Server\Protocol\Clients;

use Illuminate\Http\Request;
use Lock\Server\Shared\Clients\Client;
use Lock\Server\Shared\Clients\ClientAuthenticationException;
use Lock\Server\Shared\Clients\Clients;
use Lock\Server\Shared\Clients\TokenEndpointAuthMethod;
use Lock\Server\Shared\Context\OidcContext;
use Lock\Server\Shared\Protocol\ClientAuthenticationFailed;
use Lock\Server\Shared\Protocol\OAuthServerException;

/**
 * RFC 6749 §2.3.1: require exactly the registered authentication method;
 * combining methods is an invalid request.
 */
final readonly class ClientAuthenticator
{
    public function __construct(private Clients $clients) {}

    /**
     * @param  string|null  $grantType  when given, the client must also be registered for this grant
     */
    public function authenticate(Request $request, ?string $grantType = null): Client
    {
        [$clientId, $secret, $method] = $this->credentials($request);

        try {
            $client = $this->clients->authenticate($clientId, $secret, $method);
        } catch (ClientAuthenticationException $exception) {
            $this->fail($request, $clientId, $exception->getMessage());
        }

        if ($grantType !== null && ! $client->hasGrantType($grantType)) {
            throw OAuthServerException::unauthorizedClient('The client is not authorized to use this grant type.');
        }

        OidcContext::rememberClient($client->clientId);

        return $client;
    }

    /**
     * Basic credentials are form-urlencoded before base64 (RFC 6749 §2.3.1).
     *
     * @return array{string, ?string, TokenEndpointAuthMethod}
     */
    private function credentials(Request $request): array
    {
        $basicUser = $request->getUser();
        $bodyClientId = $request->input('client_id');
        $bodySecret = $request->input('client_secret');

        if ($basicUser !== null) {
            if (is_string($bodySecret) && $bodySecret !== '') {
                throw OAuthServerException::invalidRequest('The client used more than one authentication method.');
            }

            $clientId = urldecode($basicUser);

            if (is_string($bodyClientId) && $bodyClientId !== '' && $bodyClientId !== $clientId) {
                throw OAuthServerException::invalidRequest('The client_id parameter does not match the Authorization header.');
            }

            return [$clientId, urldecode((string) $request->getPassword()), TokenEndpointAuthMethod::ClientSecretBasic];
        }

        if (! is_string($bodyClientId) || $bodyClientId === '') {
            throw OAuthServerException::invalidClient('No client authentication included.');
        }

        if (is_string($bodySecret) && $bodySecret !== '') {
            return [$bodyClientId, $bodySecret, TokenEndpointAuthMethod::ClientSecretPost];
        }

        return [$bodyClientId, null, TokenEndpointAuthMethod::None];
    }

    private function fail(Request $request, string $clientId, string $reason): never
    {
        event(new ClientAuthenticationFailed($request->path(), $reason, $clientId));

        throw OAuthServerException::invalidClient();
    }
}
