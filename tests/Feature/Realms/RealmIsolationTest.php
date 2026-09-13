<?php

declare(strict_types=1);

use Lock\Server\Authentication\PasswordResetTokens;
use Lock\Server\Brokering\Models\SocialAccount;
use Lock\Server\Brokering\SocialAccountManager;
use Lock\Server\Clients\ClientRepository;
use Lock\Server\Consents\ConsentRepository;
use Lock\Server\Realms\ConfiguredRealm;
use Lock\Server\Shared\Brokering\SocialUser;
use Lock\Server\Shared\Realms\IssuerResolver;
use Lock\Server\Shared\Realms\Realm;
use Lock\Server\Shared\Realms\RealmResolver;
use Lock\Server\Shared\SigningKeys\Keyring;
use Lock\Server\SigningKeys\DatabaseSigningKeyStore;
use Lock\Server\SigningKeys\SigningKeyGenerator;
use Lock\Server\SigningKeys\SigningKeyPair;
use Lock\Server\SigningKeys\SigningKeyStore;
use Lock\Server\SigningKeys\StoredKeyring;
use Lock\Server\Tokens\Models\AccessToken;
use Lock\Server\Tokens\Models\RefreshToken;
use Lock\Server\Tokens\PresentedTokenResolver;
use Lock\Server\Tokens\TokenInspector;
use Workbench\App\Models\User;

function enterRealm(string $realm): void
{
    app()->instance(RealmResolver::class, new readonly class($realm) implements RealmResolver
    {
        public function __construct(private string $realm) {}

        public function current(): Realm
        {
            return new ConfiguredRealm($this->realm);
        }
    });
}

it('does not resolve a client from another realm', function (): void {
    enterRealm('acme');
    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/cb']);

    expect(app(ClientRepository::class)->findActive($client->client_id))->not->toBeNull();

    enterRealm('globex');

    expect(app(ClientRepository::class)->findActive($client->client_id))->toBeNull()
        ->and(app(ClientRepository::class)->find($client->client_id))->toBeNull();
});

it('allows the same client_id in two realms', function (): void {
    enterRealm('acme');
    $first = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/cb']);
    $first->forceFill(['client_id' => 'shared-name'])->save();

    enterRealm('globex');
    $second = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/cb']);
    $second->forceFill(['client_id' => 'shared-name'])->save();

    expect(app(ClientRepository::class)->findActive('shared-name')?->key)->toBe($second->getKey());

    enterRealm('acme');

    expect(app(ClientRepository::class)->findActive('shared-name')?->key)->toBe($first->getKey());
});

it('does not resolve an access token from another realm', function (): void {
    enterRealm('acme');
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/cb']);

    AccessToken::factory()->forClient($client)->forUser($user)->create(['id' => 'token-in-acme']);

    expect(AccessToken::query()->inRealm()->whereKey('token-in-acme')->exists())->toBeTrue();

    enterRealm('globex');

    expect(AccessToken::query()->inRealm()->whereKey('token-in-acme')->exists())->toBeFalse();
});

it('keeps signing keys per realm', function (): void {
    $store = new DatabaseSigningKeyStore;
    app()->instance(SigningKeyStore::class, $store);
    app()->instance(Keyring::class, new StoredKeyring($store));

    enterRealm('acme');
    $store->rotate(new SigningKeyGenerator($store, app(RealmResolver::class))->generate());
    $acmeKid = $store->signingKey()->kid();

    enterRealm('globex');
    $store->rotate(new SigningKeyGenerator($store, app(RealmResolver::class))->generate());
    $globexKid = $store->signingKey()->kid();

    expect($globexKid)->not->toBe($acmeKid)
        ->and(array_map(fn (SigningKeyPair $key): string => $key->kid(), $store->verificationKeys()))->toBe([$globexKid]);

    enterRealm('acme');

    expect($store->signingKey()->kid())->toBe($acmeKid);
});

it('does not resolve a token through the inspector across realms', function (): void {
    enterRealm('acme');
    generateRealmSigningKey();
    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    $this->client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/cb']);

    $jwt = resourceServerBearer($this, [app(IssuerResolver::class)->url()]);

    expect(app(TokenInspector::class)->accessToken($jwt))->not->toBeNull();

    enterRealm('globex');
    generateRealmSigningKey();

    expect(app(TokenInspector::class)->accessToken($jwt))->toBeNull();
});

it('does not resolve a refresh token from another realm', function (): void {
    enterRealm('acme');
    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    $this->client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/cb']);

    [$value] = issueRefreshToken($this);

    expect(RefreshToken::query()->inRealm()->whereKey($value)->exists())->toBeTrue()
        ->and(app(PresentedTokenResolver::class)->resolve($value, 'refresh_token'))->not->toBeNull();

    enterRealm('globex');

    expect(RefreshToken::query()->inRealm()->whereKey($value)->exists())->toBeFalse()
        ->and(app(PresentedTokenResolver::class)->resolve($value, 'refresh_token'))->toBeNull();
});

it('keeps social accounts per realm, so one upstream identity may link to a different user in each', function (): void {
    $socialUser = new SocialUser(
        id: 'g-123',
        email: 'm@example.com',
        emailVerified: true,
        name: 'M',
        nickname: null,
        avatar: null,
        raw: ['sub' => 'g-123'],
        accessToken: 'at-1',
    );

    enterRealm('acme');
    $acmeUser = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    app(SocialAccountManager::class)->link($acmeUser, 'google', $socialUser);

    expect(app(SocialAccountManager::class)->findAccount('google', 'g-123')?->user_id)->toBe((string) $acmeUser->id);

    enterRealm('globex');

    expect(app(SocialAccountManager::class)->findAccount('google', 'g-123'))->toBeNull();

    $globexUser = User::create(['name' => 'G', 'email' => 'g@example.com', 'password' => 'x']);
    app(SocialAccountManager::class)->link($globexUser, 'google', $socialUser);

    expect(app(SocialAccountManager::class)->findAccount('google', 'g-123')?->user_id)->toBe((string) $globexUser->id)
        ->and(SocialAccount::query()->count())->toBe(2);
});

it('keeps consents per realm', function (): void {
    enterRealm('acme');
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/cb']);

    $resource = ['https://api.internal/orders'];

    app(ConsentRepository::class)->grant((string) $user->id, $client->snapshot(), ['openid'], $resource);

    expect(app(ConsentRepository::class)->covers((string) $user->id, (string) $client->getKey(), ['openid'], $resource))->toBeTrue();

    enterRealm('globex');

    expect(app(ConsentRepository::class)->covers((string) $user->id, (string) $client->getKey(), ['openid'], $resource))->toBeFalse();
});

it('keeps a pending password reset per realm, so requesting one does not cancel another realm\'s', function (): void {
    enterRealm('acme');
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    $acmeToken = app(PasswordResetTokens::class)->create($user);

    enterRealm('globex');
    $globexToken = app(PasswordResetTokens::class)->create($user);

    expect(app(PasswordResetTokens::class)->exists($user, $globexToken))->toBeTrue()
        ->and(app(PasswordResetTokens::class)->exists($user, $acmeToken))->toBeFalse();

    enterRealm('acme');

    expect(app(PasswordResetTokens::class)->exists($user, $acmeToken))->toBeTrue();
});
