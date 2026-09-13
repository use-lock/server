<?php

declare(strict_types=1);

/**
 * RFC 8176 (amr value per provider)
 */

use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use Illuminate\Testing\TestResponse;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lock\Server\Authentication\Context\LoginState;
use Lock\Server\Authentication\Pipeline\PostLoginPipeline;
use Lock\Server\Brokering\Models\SocialAccount;
use Lock\Server\Brokering\PendingSocialRedirect;
use Lock\Server\Credentials\TotpFactorProvider;
use Lock\Server\Shared\Brokering\SocialAuthenticationException;
use Lock\Server\Shared\Brokering\SocialUser;
use Lock\Server\SigningKeys\Jwk;
use Workbench\App\Models\User;

function enableCorpIdp(): void
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
 * @param  array<string, mixed>  $claims
 */
function corpIdToken(array $claims, string $nonce): string
{
    $config = Configuration::forAsymmetricSigner(
        new Sha256,
        InMemory::file(__DIR__.'/../../fixtures/oauth-private.key'),
        InMemory::file(__DIR__.'/../../fixtures/oauth-public.key'),
    );

    $now = new DateTimeImmutable;
    $builder = $config->builder()
        ->withHeader('kid', Jwk::fromPem(file_get_contents(__DIR__.'/../../fixtures/oauth-public.key'))['kid'])
        ->issuedBy('https://idp.test')
        ->permittedFor('client-1')
        ->relatedTo((string) $claims['sub'])
        ->issuedAt($now)
        ->expiresAt($now->modify('+1 hour'))
        ->withClaim('nonce', $nonce);

    foreach ($claims as $name => $value) {
        if ($name !== 'sub') {
            $builder = $builder->withClaim($name, $value);
        }
    }

    return $builder->getToken($config->signer(), $config->signingKey())->toString();
}

/**
 * @param  array<string, mixed>  $claims
 * @return TestResponse<RedirectResponse>
 */
function completeSocialLogin(mixed $test, array $claims = []): TestResponse
{
    enableCorpIdp();

    $test->get(route('identity.social.redirect', ['provider' => 'corp']));
    $pending = session(PendingSocialRedirect::SESSION_KEY);

    $idToken = corpIdToken($claims + [
        'sub' => 'upstream-1',
        'email' => 'm@example.com',
        'email_verified' => true,
        'name' => 'M',
    ], $pending['nonce']);

    Http::fake([
        'https://idp.test/token' => Http::response([
            'access_token' => 'up-at',
            'expires_in' => 3600,
            'id_token' => $idToken,
            'token_type' => 'Bearer',
        ]),
    ]);

    return $test->get(route('identity.social.callback', ['provider' => 'corp'])
        .'?'.http_build_query(['code' => 'code-1', 'state' => $pending['state']]));
}

it('logs in an existing user via verified email link and records the provider amr', function (): void {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);

    app(PostLoginPipeline::class)->register(function ($event, $api): void {
        $api->setIdTokenClaim('department', 'engineering');
    });

    completeSocialLogin($this)->assertRedirect('/dashboard');

    $this->assertAuthenticatedAs($user, 'identity');
    expect(session('oidc.id_token_claims'))->toBe(['department' => 'engineering']);
    expect(session(LoginState::AMR_KEY))->toBe(['corp'])
        ->and(SocialAccount::query()->where('provider', 'corp')->where('provider_user_id', 'upstream-1')->exists())->toBeTrue();
});

it('provisions a user just-in-time via the registered action', function (): void {
    createUsersFromSocialUsing(fn (SocialUser $socialUser): User => User::create([
        'name' => $socialUser->name ?? 'Unknown',
        'email' => $socialUser->email,
        'password' => Str::random(40),
    ]));

    completeSocialLogin($this)->assertRedirect('/dashboard');

    expect(User::query()->where('email', 'm@example.com')->exists())->toBeTrue();
    $this->assertAuthenticated('identity');
});

it('rejects the login with a friendly error when the provisioning action refuses the identity', function (): void {
    createUsersFromSocialUsing(function (SocialUser $socialUser): User {
        throw new SocialAuthenticationException('The account has no verified email address.');
    });

    completeSocialLogin($this)
        ->assertRedirect(route('identity.login'))
        ->assertSessionHasErrors('social');

    $this->assertGuest('identity');
});

it('rejects the login when no account can be resolved', function (): void {
    config()->set('oidc.social.auto_provision', false);

    completeSocialLogin($this)
        ->assertRedirect(route('identity.login'))
        ->assertSessionHasErrors('social');

    $this->assertGuest('identity');
});

it('denies the login when a postLogin hook rejects it', function (): void {
    User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);
    app(PostLoginPipeline::class)->register(function ($event, $api): void {
        $api->deny('blocked');
    });

    completeSocialLogin($this)
        ->assertRedirect(route('identity.login'))
        ->assertSessionHasErrors('social');

    $this->assertGuest('identity');
});

it('sends an MFA-enrolled user to the two-factor challenge instead of logging in', function (): void {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);
    $factor = app(TotpFactorProvider::class)->enroll($user);
    $factor->forceFill(['confirmed_at' => now()])->save();

    completeSocialLogin($this)->assertRedirect(route('identity.two-factor.login'));

    $this->assertGuest('identity');
    expect(session('login.id'))->toBe($user->getAuthIdentifier())
        ->and(session('login.factor'))->toBe('totp');
});
