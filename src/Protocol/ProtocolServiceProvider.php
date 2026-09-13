<?php

declare(strict_types=1);

namespace Lock\Server\Protocol;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Foundation\Exceptions\Handler;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\ServiceProvider;
use Lock\Server\Protocol\Authorize\PendingAuthorizationRequest;
use Lock\Server\Protocol\Clients\ClientAuthenticator;
use Lock\Server\Protocol\Http\Controllers\AuthorizeController;
use Lock\Server\Protocol\Http\OAuthErrorRenderer;
use Lock\Server\Protocol\Ui\Pages\LogoutConfirmationPage;
use Lock\Server\Protocol\Ui\Views\LogoutConfirmationView;
use Lock\Server\Shared\Authentication\IdentityGuard;
use Lock\Server\Shared\Authentication\PendingAuthorization;
use Lock\Server\Shared\Protocol\OAuthServerException;
use Lock\Server\Shared\Realms\RealmResolver;
use Lock\Server\Shared\Tokens\Grant;
use Symfony\Component\HttpFoundation\Response;

class ProtocolServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->bind(PendingAuthorization::class, PendingAuthorizationRequest::class);
        $this->app->bind(LogoutConfirmationView::class, LogoutConfirmationPage::class);

        $this->callAfterResolving(ExceptionHandler::class, function (ExceptionHandler $handler): void {
            if ($handler instanceof Handler) {
                $handler->dontReport(OAuthServerException::class);
                $handler->renderable(fn (OAuthServerException $exception): Response => $this->app->make(OAuthErrorRenderer::class)->render($exception));
                $handler->renderable(fn (AuthenticationException $exception, Request $request): ?Response => $this->app->make(OAuthErrorRenderer::class)->renderAuthentication($exception, $request));
            }
        });

        $this->app->when(AuthorizeController::class)
            ->needs(StatefulGuard::class)
            ->give(fn () => Auth::guard(IdentityGuard::name()));

        $this->app->bind(TokenEndpoint::class, fn (Application $app): TokenEndpoint => new TokenEndpoint(
            $app->make(ClientAuthenticator::class),
            iterator_to_array($app->tagged(Grant::class)),
            $app->make(RealmResolver::class),
        ));
    }
}
