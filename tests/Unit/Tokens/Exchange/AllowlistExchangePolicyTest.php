<?php
declare(strict_types=1);

use Lock\Server\Shared\Clients\Client;
use Lock\Server\Shared\Clients\TokenEndpointAuthMethod;
use Lock\Server\Shared\Protocol\OAuthServerException;
use Lock\Server\Tokens\Exchange\AllowlistExchangePolicy;
use Lock\Server\Tokens\Exchange\ExchangeGrantResult;
use Lock\Server\Tokens\Exchange\ExchangeRequest;

/** @param  string[]  $audiences */
function exchangePolicyClient(array $audiences = ['https://api.internal/orders']): Client
{
    return new Client(
        key: 'client-key',
        clientId: 'client-key',
        realm: 'default',
        name: 'Client',
        authMethod: TokenEndpointAuthMethod::None,
        redirectUris: [],
        postLogoutRedirectUris: [],
        grantTypes: [],
        defaultScopeAssignments: [],
        optionalScopeAssignments: [],
        allowedAudiences: $audiences,
        backchannelLogoutUri: null,
        backchannelLogoutSessionRequired: false,
        consentRequired: true,
        confidential: false,
        revoked: false,
    );
}

/**
 * @param  string[]  $aud
 * @param  string[]  $scopes
 * @return array<string, mixed>
 */
function exchangePolicySubjectClaims(string $clientId, array $aud, array $scopes): array
{
    return ['sub' => '42', 'aud' => $aud, 'scope' => implode(' ', $scopes), 'client_id' => $clientId];
}

it('authorizes a reciprocal, allowlisted, narrowed exchange', function (): void {
    $client = exchangePolicyClient();
    $request = new ExchangeRequest(
        $client,
        exchangePolicySubjectClaims($client->clientId, [$client->clientId], ['openid', 'email', 'orders:read']),
        'https://api.internal/orders',
        ['orders:read'],
        time() + 3600,
    );

    $result = (new AllowlistExchangePolicy)->authorize($request);

    expect($result->userId)->toBe('42')
        ->and($result->scopes)->toBe(['orders:read'])
        ->and($result->audience)->toBe(['https://api.internal/orders'])
        ->and($result->expiresAt)->toBeLessThanOrEqual(time() + 3600);
});

it('rejects a policy violation with the matching OAuth error type', function (
    bool $withSub,
    string $audience,
    ?array $requestedScopes,
    string $errorType,
): void {
    $client = exchangePolicyClient();
    $claims = exchangePolicySubjectClaims($client->clientId, [$client->clientId], ['openid']);

    if (! $withSub) {
        unset($claims['sub']);
    }

    $request = new ExchangeRequest($client, $claims, $audience, $requestedScopes, time() + 3600);

    expectExchangeDenied(fn (): ExchangeGrantResult => (new AllowlistExchangePolicy)->authorize($request), $errorType);
})->with([
    'missing sub claim' => [false, 'https://api.internal/orders', null, 'invalid_grant'],
    'unlisted target audience' => [true, 'https://evil/api', null, 'invalid_target'],
    'scope widening' => [true, 'https://api.internal/orders', ['admin'], 'invalid_scope'],
]);

it('rejects when the requesting client is not in the subject token audience (reciprocity)', function (): void {
    $client = exchangePolicyClient();
    $request = new ExchangeRequest($client, exchangePolicySubjectClaims('someone-else', ['other-service'], ['openid']), 'https://api.internal/orders', null, time() + 3600);

    (new AllowlistExchangePolicy)->authorize($request);
})->throws(OAuthServerException::class);

it('defaults issued scopes to the subject scopes when none requested', function (): void {
    $client = exchangePolicyClient();
    $request = new ExchangeRequest($client, exchangePolicySubjectClaims($client->clientId, [$client->clientId], ['openid', 'email']), 'https://api.internal/orders', null, time() + 3600);

    expect((new AllowlistExchangePolicy)->authorize($request)->scopes)->toBe(['openid', 'email']);
});
