<?php

declare(strict_types=1);

namespace Lock\Server\Tokens;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;
use Lock\Server\Shared\Maintenance\RealmDeleting;
use Lock\Server\Shared\Maintenance\UserDeleting;
use Lock\Server\Shared\Tokens\AccessTokenMinter;
use Lock\Server\Shared\Tokens\AccessTokenRevoker;
use Lock\Server\Shared\Tokens\AuthorizationCodes;
use Lock\Server\Shared\Tokens\Grant;
use Lock\Server\Shared\Tokens\PresentedTokens;
use Lock\Server\Shared\Tokens\SignedJwtParser;
use Lock\Server\Shared\Tokens\TokenExchange;
use Lock\Server\Tokens\Contracts\ExchangePolicy;
use Lock\Server\Tokens\Exchange\AllowlistExchangePolicy;
use Lock\Server\Tokens\Exchange\TokenExchanger;
use Lock\Server\Tokens\Grants\AuthorizationCodeGrant;
use Lock\Server\Tokens\Grants\ClientCredentialsGrant;
use Lock\Server\Tokens\Grants\RefreshTokenGrant;
use Lock\Server\Tokens\Grants\TokenExchangeGrant;
use Lock\Server\Tokens\Guard\AccessTokenGuard;
use Lock\Server\Tokens\Listeners\DeleteRealmData;
use Lock\Server\Tokens\Listeners\DeleteUserData;
use Lock\Server\Tokens\Models\AccessToken;
use Lock\Server\Tokens\Models\AuthenticationContext;
use Lock\Server\Tokens\Models\AuthorizationCode;
use Lock\Server\Tokens\Models\RefreshToken;
use Lock\Server\Tokens\Pipeline\AccessTokenPipeline;

class TokensServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->tag([RefreshToken::class, AccessToken::class, AuthorizationCode::class, AuthenticationContext::class], 'oidc.prunable');

        $this->app->tag([AuthorizationCodeGrant::class, RefreshTokenGrant::class, ClientCredentialsGrant::class, TokenExchangeGrant::class], Grant::class);

        $apiGuard = (string) config('oidc.auth.api_guard', 'oidc');

        if (! config()->has("auth.guards.{$apiGuard}")) {
            config()->set("auth.guards.{$apiGuard}", [
                'driver' => 'oidc',
                'provider' => (string) config('oidc.auth.provider', 'users'),
            ]);
        }

        Auth::resolved(fn ($auth) => $auth->extend('oidc', fn ($app, $name, array $config): AccessTokenGuard => tap(
            new AccessTokenGuard(
                $app->make(TokenInspector::class),
                $auth->createUserProvider($config['provider'] ?? null),
                $app->make('request'),
            ),
            fn (AccessTokenGuard $guard) => $app->refresh('request', $guard, 'setRequest'),
        )));

        $this->app->singleton(AuthorizationCodes::class, AuthorizationCodeIssuer::class);
        $this->app->singleton(PresentedTokens::class, PresentedTokenResolver::class);
        $this->app->singleton(AccessTokenPipeline::class);
        $this->app->bind(SignedJwtParser::class, TokenInspector::class);
        $this->app->singleton(AccessTokenMinter::class, JwtAccessTokenMinter::class);
        $this->app->singleton(AccessTokenRevoker::class, TokenRevoker::class);
        $this->app->singleton(ExchangePolicy::class, AllowlistExchangePolicy::class);
        $this->app->singleton(TokenExchanger::class);
        $this->app->alias(TokenExchanger::class, TokenExchange::class);
    }

    public function boot(): void
    {
        Event::listen(UserDeleting::class, DeleteUserData::class);
        Event::listen(RealmDeleting::class, DeleteRealmData::class);

    }
}
