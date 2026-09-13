<?php

declare(strict_types=1);

use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Facades\Http;
use Illuminate\Testing\TestResponse;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lock\Server\Brokering\Models\SocialAccount;
use Lock\Server\Brokering\PendingSocialRedirect;
use Lock\Server\Brokering\SocialAccountManager;
use Lock\Server\Shared\Brokering\SocialUser;
use Lock\Server\SigningKeys\Jwk;
use Workbench\App\Models\User;

function enableCorpForLinking(): void
{
    config()->set('oidc.social.providers.corp', [
        'driver' => 'oidc',
        'issuer' => 'https://idp.test',
        'client_id' => 'client-1',
        'client_secret' => 'shhh',
    ]);

    Http::fake([
        'https://idp.test/.well-known/openid-configuration' => Http::response([
            'issuer' => 'https://idp.test',
            'authorization_endpoint' => 'https://idp.test/authorize',
            'token_endpoint' => 'https://idp.test/token',
            'jwks_uri' => 'https://idp.test/jwks',
        ]),
        'https://idp.test/jwks' => Http::response([
            'keys' => [Jwk::fromPem(file_get_contents(__DIR__.'/../../fixtures/oauth-public.key'))],
        ]),
    ]);
}

/**
 * @return TestResponse<RedirectResponse>
 */
function linkCallbackFor(mixed $test, string $sub = 'upstream-1'): TestResponse
{
    $pending = session(PendingSocialRedirect::SESSION_KEY);

    $config = Configuration::forAsymmetricSigner(
        new Sha256,
        InMemory::file(__DIR__.'/../../fixtures/oauth-private.key'),
        InMemory::file(__DIR__.'/../../fixtures/oauth-public.key'),
    );
    $now = new DateTimeImmutable;
    $idToken = $config->builder()
        ->withHeader('kid', Jwk::fromPem(file_get_contents(__DIR__.'/../../fixtures/oauth-public.key'))['kid'])
        ->issuedBy('https://idp.test')
        ->permittedFor('client-1')
        ->relatedTo($sub)
        ->issuedAt($now)
        ->expiresAt($now->modify('+1 hour'))
        ->withClaim('nonce', $pending['nonce'])
        ->withClaim('email', 'linked@example.com')
        ->withClaim('email_verified', true)
        ->getToken($config->signer(), $config->signingKey())
        ->toString();

    Http::fake([
        'https://idp.test/token' => Http::response(['access_token' => 'up-at', 'id_token' => $idToken, 'token_type' => 'Bearer']),
    ]);

    return $test->get(route('identity.social.callback', ['provider' => 'corp'])
        .'?'.http_build_query(['code' => 'code-1', 'state' => $pending['state']]));
}

it('links a provider to the authenticated user', function (): void {
    enableCorpForLinking();
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);

    $this->actingAs($user, 'identity')
        ->withSession(['auth.password_confirmed_at' => time()])
        ->get(route('identity.social.link', ['provider' => 'corp']))
        ->assertRedirect();

    expect(session(PendingSocialRedirect::SESSION_KEY)['intent'])->toBe('link');

    linkCallbackFor($this)->assertRedirect('/dashboard')->assertSessionHas('status', 'social-account-linked');

    $account = SocialAccount::query()->sole();
    expect($account->provider)->toBe('corp')
        ->and($account->provider_user_id)->toBe('upstream-1')
        ->and($account->user_id)->toBe((string) $user->id);
});

it('refuses to link an identity already attached to another user', function (): void {
    enableCorpForLinking();
    $other = User::create(['name' => 'O', 'email' => 'other@example.com', 'password' => 'secret']);
    app(SocialAccountManager::class)->link($other, 'corp', new SocialUser('upstream-1', 'other@example.com', true, 'O', null, null));

    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);

    $this->actingAs($user, 'identity')
        ->withSession(['auth.password_confirmed_at' => time()])
        ->get(route('identity.social.link', ['provider' => 'corp']));

    linkCallbackFor($this)->assertRedirect('/dashboard')->assertSessionHasErrors('social');

    $account = SocialAccount::query()->sole();
    expect($account->user_id)->toBe((string) $other->id)
        ->and($account->email)->toBe('other@example.com')
        ->and($account->name)->toBe('O')
        ->and($account->access_token)->toBeNull();
});

it('rejects a link-intent callback when the identity session is gone', function (): void {
    enableCorpForLinking();
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);

    $this->actingAs($user, 'identity')
        ->withSession(['auth.password_confirmed_at' => time()])
        ->get(route('identity.social.link', ['provider' => 'corp']))
        ->assertRedirect();

    auth('identity')->logout();

    linkCallbackFor($this)
        ->assertRedirect(route('identity.login'))
        ->assertSessionHasErrors('social');

    expect(SocialAccount::query()->count())->toBe(0);
});

it('requires authentication to start linking', function (): void {
    enableCorpForLinking();

    $this->get(route('identity.social.link', ['provider' => 'corp']))->assertRedirect();
    expect(session(PendingSocialRedirect::SESSION_KEY))->toBeNull();
});

it('unlinks an account owned by the user', function (): void {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);
    $account = app(SocialAccountManager::class)->link($user, 'corp', new SocialUser('upstream-1', 'm@example.com', true, 'M', null, null));

    $this->actingAs($user, 'identity')
        ->withSession(['auth.password_confirmed_at' => time()])
        ->delete(route('identity.social.destroy', ['socialAccount' => $account->id]))
        ->assertRedirect();

    expect(SocialAccount::query()->count())->toBe(0);
});

it('forbids unlinking another user\'s account', function (): void {
    $owner = User::create(['name' => 'O', 'email' => 'o@example.com', 'password' => 'secret']);
    $account = app(SocialAccountManager::class)->link($owner, 'corp', new SocialUser('upstream-1', 'o@example.com', true, 'O', null, null));

    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);

    $this->actingAs($user, 'identity')
        ->withSession(['auth.password_confirmed_at' => time()])
        ->delete(route('identity.social.destroy', ['socialAccount' => $account->id]))
        ->assertForbidden();

    expect(SocialAccount::query()->count())->toBe(1);
});

it('uses an external Inertia location when linking a provider', function (): void {
    enableCorpForLinking();
    $user = User::factory()->create();

    $response = $this->actingAs($user, 'identity')
        ->withSession(['auth.password_confirmed_at' => time()])
        ->get(route('identity.social.link', ['provider' => 'corp']), ['X-Inertia' => 'true'])
        ->assertStatus(409);

    expect($response->headers->get('X-Inertia-Location'))->toStartWith('https://idp.test/authorize?')
        ->and(session(PendingSocialRedirect::SESSION_KEY)['intent'])->toBe('link');
});
