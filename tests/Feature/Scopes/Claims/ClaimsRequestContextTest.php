<?php

declare(strict_types=1);

use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;
use Lock\Server\Clients\ClientRepository;
use Lock\Server\Shared\Realms\IssuerResolver;
use Lock\Server\Shared\Scopes\ClaimsAudience;
use Lock\Server\Shared\Scopes\ClaimsRequest;
use Lock\Server\Shared\Scopes\ClaimsResolver;
use Lock\Server\Tokens\IdTokenBuilder;
use Lock\Server\Tokens\IdTokenRequest;
use Workbench\App\Models\User;

final class ClaimsContextRecorder implements ClaimsResolver
{
    /** @var list<ClaimsRequest> */
    public array $seen = [];

    /** @return array<string, mixed> */
    public function resolve(ClaimsRequest $request): array
    {
        $this->seen[] = $request;

        return [
            'seen_audience' => $request->audience->value,
            'seen_client' => $request->clientId,
            'seen_scopes' => $request->scopes,
            'seen_openid' => $request->hasScope('openid'),
        ];
    }
}

function recordClaimsRequests(): ClaimsContextRecorder
{
    $recorder = new ClaimsContextRecorder;

    app()->instance(ClaimsResolver::class, $recorder);

    return $recorder;
}

/** @param  list<string>  $scopes */
function claimsContextIdToken(User $user, string $clientId, array $scopes): UnencryptedToken
{
    $parsed = new Parser(new JoseEncoder)->parse(
        app(IdTokenBuilder::class)->build(new IdTokenRequest(
            userId: (string) $user->id,
            clientId: $clientId,
            scopes: $scopes,
            accessToken: 'access-token-jwt',
        )),
    );

    if (! $parsed instanceof UnencryptedToken) {
        throw new RuntimeException('Expected an unencrypted token.');
    }

    return $parsed;
}

it('hands the id_token builder the client, scopes and id_token audience', function (): void {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    $seen = recordClaimsRequests();

    $parsed = claimsContextIdToken($user, 'rp-one', ['openid', 'profile']);

    expect($seen->seen)->toHaveCount(1)
        ->and($seen->seen[0]->user->getAuthIdentifier())->toBe($user->getAuthIdentifier())
        ->and($parsed->claims()->get('seen_audience'))->toBe(ClaimsAudience::IdToken->value)
        ->and($parsed->claims()->get('seen_client'))->toBe('rp-one')
        ->and($parsed->claims()->get('seen_scopes'))->toBe(['openid', 'profile'])
        ->and($parsed->claims()->get('seen_openid'))->toBeTrue()
        ->and(claimsContextIdToken($user, 'rp-two', ['openid'])->claims()->get('seen_client'))->toBe('rp-two');
});

it('hands userinfo the client, scopes and userinfo audience', function (): void {
    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    $this->client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/cb']);
    recordClaimsRequests();

    $bearer = resourceServerBearer($this, [app(IssuerResolver::class)->url()]);

    $response = $this->getJson('/oauth/userinfo', ['Authorization' => 'Bearer '.$bearer])->assertOk();

    expect($response->json('seen_audience'))->toBe(ClaimsAudience::Userinfo->value)
        ->and($response->json('seen_scopes'))->toBe(['openid'])
        ->and($response->json('seen_client'))->toBe((string) $this->client->id);
});
