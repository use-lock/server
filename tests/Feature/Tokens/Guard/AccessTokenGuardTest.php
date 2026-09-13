<?php

declare(strict_types=1);

/**
 * RFC 6750 §3 (bearer challenges from the auth:oidc guard); RFC 9068 §4 (typ, iss, aud); RFC 9728 §5.1 (resource_metadata)
 */

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lock\Server\Clients\ClientRepository;
use Lock\Server\Shared\Realms\IssuerResolver;
use Lock\Server\SigningKeys\Jwk;
use Lock\Server\Tokens\Guard\ClientPrincipal;
use Lock\Server\Tokens\Models\AccessToken;
use Workbench\App\Models\User;

const GUARD_RESOURCE_METADATA = 'resource_metadata="http://localhost/.well-known/oauth-protected-resource"';

beforeEach(function (): void {
    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    $this->client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/cb']);

    Route::middleware('auth:oidc')->get('/guarded', fn (): array => ['id' => auth()->id()]);
});

/**
 * An otherwise valid at+jwt signed with the realm's key but carrying a foreign
 * issuer, with a persisted row so only the iss check can reject it.
 */
function bearerIssuedElsewhere(mixed $test): string
{
    $jti = Str::random(80);
    $now = new DateTimeImmutable;

    $config = Configuration::forAsymmetricSigner(
        new Sha256,
        InMemory::plainText(signingPrivateKey()),
        InMemory::plainText(signingPublicKey()),
    );

    $jwt = $config->builder()
        ->withHeader('typ', 'at+jwt')
        ->withHeader('kid', Jwk::fromPem(signingPublicKey())['kid'])
        ->issuedBy('https://other-issuer.test')
        ->identifiedBy($jti)
        ->issuedAt($now)
        ->canOnlyBeUsedAfter($now)
        ->expiresAt($now->modify('+1 hour'))
        ->relatedTo((string) $test->user->id)
        ->permittedFor((string) $test->client->id)
        ->withClaim('client_id', (string) $test->client->id)
        ->withClaim('scope', 'openid')
        ->getToken($config->signer(), $config->signingKey())
        ->toString();

    (new AccessToken)->forceFill([
        'realm' => AccessToken::currentRealm(),
        'id' => $jti,
        'user_id' => $test->user->id,
        'client_id' => $test->client->id,
        'scopes' => ['openid'],
        'expires_at' => now()->addHour(),
    ])->save();

    return $jwt;
}

it('authenticates a token the realm issued and resolves the user from sub', function (): void {
    $jwt = resourceServerBearer($this);

    $this->getJson('/guarded', ['Authorization' => "Bearer $jwt"])
        ->assertOk()
        ->assertJson(['id' => $this->user->id]);
});

// RFC 9068 §4 — aud must name this resource; the issuing client is not an audience
it('accepts only tokens addressed to the issuer or a registered resource', function (): void {
    config(['oidc.resources' => ['https://api.example/orders' => []]]);

    $accepted = resourceServerBearer($this, ['https://api.example/orders']);
    $foreign = resourceServerBearer($this, ['https://other.example/api']);
    $issuerOnly = resourceServerBearer($this, [app(IssuerResolver::class)->url()]);
    $clientOnly = resourceServerBearer($this, [(string) $this->client->client_id]);

    $this->getJson('/guarded', ['Authorization' => "Bearer $accepted"])->assertOk();

    // The guard instance caches the user it resolved; drop it so each bearer is validated afresh.
    Auth::forgetGuards();
    $this->getJson('/guarded', ['Authorization' => "Bearer $foreign"])->assertUnauthorized();

    // The issuer stays an audience next to the registered resources.
    Auth::forgetGuards();
    $this->getJson('/guarded', ['Authorization' => "Bearer $issuerOnly"])->assertOk();

    Auth::forgetGuards();
    $this->getJson('/guarded', ['Authorization' => "Bearer $clientOnly"])
        ->assertUnauthorized()
        ->assertJsonPath('error', 'invalid_token');
});

it('authenticates a userless token as the client it was issued to', function (): void {
    $machine = app(ClientRepository::class)->createClientCredentialsGrantClient('M2M');
    $jwt = clientCredentialsBearer($machine, ['orders.read']);

    Route::middleware('auth:oidc')->get('/machine', function (Request $request): array {
        $principal = $request->user();

        return [
            'principal' => $principal === null ? null : $principal::class,
            'id' => $principal?->getAuthIdentifier(),
            'scopes' => $principal?->currentAccessToken()?->scopes(),
        ];
    });

    $this->getJson('/machine', ['Authorization' => "Bearer $jwt"])
        ->assertOk()
        ->assertExactJson([
            'principal' => ClientPrincipal::class,
            'id' => $machine->client_id,
            'scopes' => ['orders.read'],
        ]);
});

it('rejects a userless token whose client is revoked or gone', function (string $case): void {
    $machine = app(ClientRepository::class)->createClientCredentialsGrantClient('M2M');
    $jwt = clientCredentialsBearer($machine);

    $case === 'revoked'
        ? $machine->forceFill(['revoked_at' => now()])->save()
        : $machine->delete();

    $this->getJson('/guarded', ['Authorization' => "Bearer $jwt"])
        ->assertUnauthorized()
        ->assertJsonPath('error', 'invalid_token');
})->with(['revoked', 'deleted']);

// RFC 6750 §3.1 — no credentials presented: a challenge without an error code
it('challenges a request without a bearer token and names no error', function (): void {
    $this->getJson('/guarded')
        ->assertUnauthorized()
        ->assertHeader('WWW-Authenticate', 'Bearer realm="default", '.GUARD_RESOURCE_METADATA)
        ->assertHeader('Cache-Control', 'no-store, private')
        ->assertNoContent(401);

    Route::get('/login', fn (): string => 'login')->name('login');
    Route::getRoutes()->refreshNameLookups();

    $this->get('/guarded')
        ->assertUnauthorized()
        ->assertHeader('WWW-Authenticate', 'Bearer realm="default", '.GUARD_RESOURCE_METADATA);
});

it('answers a rejected bearer token with invalid_token', function (string $case): void {
    $jwt = match ($case) {
        'garbage' => 'garbage',
        'revoked' => resourceServerBearer($this, revoked: true),
        'expired' => resourceServerBearer($this, expired: true),
        'foreign issuer' => bearerIssuedElsewhere($this),
        'id_token as bearer' => persistedIdTokenAsBearer($this),
        'revoked machine token' => clientCredentialsBearer(app(ClientRepository::class)->createClientCredentialsGrantClient('M2M'), revoked: true),
        'machine token for another resource' => clientCredentialsBearer(app(ClientRepository::class)->createClientCredentialsGrantClient('M2M'), audience: ['https://other.example/api']),
        default => throw new LogicException('Unknown case.'),
    };

    $this->getJson('/guarded', ['Authorization' => "Bearer $jwt"])
        ->assertUnauthorized()
        ->assertJsonPath('error', 'invalid_token')
        ->assertHeader('WWW-Authenticate', 'Bearer realm="default", error="invalid_token", '.GUARD_RESOURCE_METADATA);
})->with([
    'garbage',
    'revoked',
    'expired',
    'foreign issuer',
    'id_token as bearer',
    'revoked machine token',
    'machine token for another resource',
]);

it('leaves other guards to Laravel', function (): void {
    Route::middleware('auth:web')->get('/session-guarded', fn (): string => 'ok');

    $this->getJson('/session-guarded')
        ->assertUnauthorized()
        ->assertHeaderMissing('WWW-Authenticate')
        ->assertJson(['message' => 'Unauthenticated.']);
});

it('challenges through the default guard when that guard is the oidc one', function (): void {
    config(['auth.defaults.guard' => 'oidc']);
    Route::middleware('auth')->get('/default-guarded', fn (): string => 'ok');

    $this->getJson('/default-guarded')
        ->assertUnauthorized()
        ->assertHeader('WWW-Authenticate', 'Bearer realm="default", '.GUARD_RESOURCE_METADATA);
});

it('leaves the default guard to Laravel when it is a session guard', function (): void {
    Route::middleware('auth')->get('/default-guarded', fn (): string => 'ok');

    $this->getJson('/default-guarded')
        ->assertUnauthorized()
        ->assertHeaderMissing('WWW-Authenticate')
        ->assertJson(['message' => 'Unauthenticated.']);
});

/**
 * The subject of a persisted token can stop resolving without the row going
 * away — a provider that scopes by tenant or hides soft-deleted users returns
 * null for a user_id the foreign key still considers valid.
 */
it('rejects a bearer whose subject the user provider no longer resolves', function (): void {
    $jwt = resourceServerBearer($this);

    Auth::provider('resolves-nobody', fn (): UserProvider => new class implements UserProvider
    {
        public function retrieveById($identifier): ?Authenticatable
        {
            return null;
        }

        public function retrieveByToken($identifier, #[SensitiveParameter] $token): ?Authenticatable
        {
            return null;
        }

        public function updateRememberToken(Authenticatable $user, #[SensitiveParameter] $token): void {}

        /** @param  array<string, mixed>  $credentials */
        public function retrieveByCredentials(#[SensitiveParameter] array $credentials): ?Authenticatable
        {
            return null;
        }

        /** @param  array<string, mixed>  $credentials */
        public function validateCredentials(Authenticatable $user, #[SensitiveParameter] array $credentials): bool
        {
            return false;
        }

        /** @param  array<string, mixed>  $credentials */
        public function rehashPasswordIfRequired(Authenticatable $user, #[SensitiveParameter] array $credentials, bool $force = false): void {}
    });

    config(['auth.providers.users.driver' => 'resolves-nobody']);
    Auth::forgetGuards();

    $this->getJson('/guarded', ['Authorization' => "Bearer $jwt"])
        ->assertUnauthorized()
        ->assertJsonPath('error', 'invalid_token');
});
