<?php

declare(strict_types=1);

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Lock\Server\Brokering\Models\SocialAccount;
use Lock\Server\Clients\ClientRepository;
use Lock\Server\Clients\Models\Client;
use Lock\Server\Consents\Models\Consent;
use Lock\Server\Credentials\Models\PasswordHistory;
use Lock\Server\Credentials\Models\RecoveryCode;
use Lock\Server\Credentials\Models\TotpFactor;
use Lock\Server\Sessions\Models\OidcSession;
use Lock\Server\Sessions\Models\SessionParticipant;
use Lock\Server\Shared\Clients\Clients;
use Lock\Server\Shared\Maintenance\RealmDeleting;
use Lock\Server\Shared\Maintenance\UserDeleting;
use Lock\Server\Shared\Realms\CurrentRealm;
use Lock\Server\Tokens\Models\AccessToken;
use Lock\Server\Tokens\Models\AuthenticationContext;
use Lock\Server\Tokens\Models\AuthorizationCode;
use Lock\Server\Tokens\Models\RefreshToken;
use Workbench\App\Models\User;

function purgeTestUser(string $name): User
{
    return User::create(['name' => $name, 'email' => "{$name}@example.com", 'password' => 'secret']);
}

function purgeTestClient(?User $owner = null): Client
{
    return app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/cb'], owner: $owner);
}

function seedHoldings(User $user, Client $client): void
{
    RefreshToken::factory()->forAccessToken(AccessToken::factory()->forClient($client)->forUser($user)->create())->create();
    AuthorizationCode::factory()->forClient($client)->forUser($user)->create();
    Consent::factory()->forClient($client)->forUser($user)->create();
    AuthenticationContext::factory()->forUser($user)->create();
    SessionParticipant::factory()->inSession(OidcSession::factory()->forUser($user)->create())->forClient($client)->create();
    passwordResetToken($user);
    SocialAccount::factory()->forUser($user)->create();
    PasswordHistory::factory()->forUser($user)->create();
    TotpFactor::factory()->forUser($user)->create();
    RecoveryCode::factory()->forUser($user)->create();
}

/** @return array<string, int> */
function packageRowCounts(?string $realm = null): array
{
    return collect(Schema::getTables())
        ->pluck('name')
        ->filter(fn (string $table): bool => str_starts_with($table, 'oidc_'))
        ->reject(fn (string $table): bool => $realm !== null && ! Schema::hasColumn($table, 'realm'))
        ->sort()
        ->mapWithKeys(fn (string $table): array => [$table => DB::table($table)->when($realm !== null, fn ($query) => $query->where('realm', $realm))->count()])
        ->all();
}

it('purges everything the package holds for a user, and nothing of anyone else', function (): void {
    $client = purgeTestClient();
    seedHoldings(purgeTestUser('bob'), $client);
    $untouched = packageRowCounts();
    $ada = purgeTestUser('ada');
    seedHoldings($ada, $client);
    CurrentRealm::runAs('other', fn () => seedHoldings($ada, purgeTestClient(owner: $ada)));

    event(new readonly class($ada) implements UserDeleting
    {
        public function __construct(private Authenticatable $subject) {}

        public function user(): Authenticatable
        {
            return $this->subject;
        }
    });

    expect(packageRowCounts())->toBe($untouched);
    $this->assertModelExists($ada);
});

it('purges the clients a user registered, with what they issued to others', function (): void {
    $ada = purgeTestUser('ada');
    $adasApp = purgeTestClient(owner: $ada);
    $clientSheUses = purgeTestClient();
    seedHoldings(purgeTestUser('bob'), $adasApp);

    event(new readonly class($ada) implements UserDeleting
    {
        public function __construct(private Authenticatable $subject) {}

        public function user(): Authenticatable
        {
            return $this->subject;
        }
    });

    expect(Client::query()->pluck('id')->all())->toBe([$clientSheUses->id])
        ->and(AccessToken::query()->where('client_id', $adasApp->id)->exists())->toBeFalse();
});

it('purges the clients a user registered under a morph alias', function (): void {
    Relation::morphMap(['user' => User::class]);
    $ada = purgeTestUser('ada');
    purgeTestClient(owner: $ada);

    event(new readonly class($ada) implements UserDeleting
    {
        public function __construct(private Authenticatable $subject) {}

        public function user(): Authenticatable
        {
            return $this->subject;
        }
    });

    expect(Client::query()->exists())->toBeFalse();
})->after(fn (): array => Relation::$morphMap = []);

it('purges a client with everything issued to it, and nothing of another client', function (): void {
    $user = purgeTestUser('ada');
    seedHoldings($user, purgeTestClient());
    $untouched = packageRowCounts();
    $client = purgeTestClient();
    RefreshToken::factory()->forAccessToken(AccessToken::factory()->forClient($client)->forUser($user)->create())->create();
    AuthorizationCode::factory()->forClient($client)->forUser($user)->create();
    Consent::factory()->forClient($client)->forUser($user)->create();
    SessionParticipant::factory()->forClient($client)->create(['session_id' => OidcSession::query()->value('id')]);

    app(Clients::class)->delete((string) $client->getKey(), $client->realm);

    expect(packageRowCounts())->toBe($untouched);
});

it('purges every row kept under a realm, and nothing of another realm', function (): void {
    CurrentRealm::runAs('globex', function (): void {
        generateRealmSigningKey();
        seedHoldings(purgeTestUser('bob'), purgeTestClient());
    });
    $globex = packageRowCounts('globex');
    CurrentRealm::runAs('acme', function (): void {
        generateRealmSigningKey();
        seedHoldings(purgeTestUser('ada'), purgeTestClient());
    });

    event(new readonly class implements RealmDeleting
    {
        public function realm(): string
        {
            return 'acme';
        }
    });

    expect(packageRowCounts('acme'))->each->toBe(0)
        ->and(packageRowCounts('globex'))->toBe($globex)
        ->and(SessionParticipant::query()->whereNotIn('session_id', OidcSession::query()->select('id'))->exists())->toBeFalse();
});
