<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;

it('rate limits every credential-handling endpoint', function (string $routeName): void {
    $route = Route::getRoutes()->getByName($routeName);

    expect($route)->not->toBeNull();

    $throttled = collect($route->gatherMiddleware())
        ->contains(fn (mixed $middleware): bool => is_string($middleware) && str_starts_with($middleware, 'throttle'));

    expect($throttled)->toBeTrue();
})->with([
    'identity.login.store',
    'identity.register.store',
    'identity.password.email',
    'identity.password.update',
    'identity.password.confirm.store',
    'identity.verification.send',
    'identity.verification.verify',
    'identity.two-factor.login.store',
    'identity.two-factor.login.options',
    'identity.two-factor.enroll',
    'identity.two-factor.enroll.confirm',
    'identity.passkey.login',
    'identity.passkey.login-options',
    'identity.passkey.confirm',
    'identity.passkey.confirm-options',
]);
