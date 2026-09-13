<?php

declare(strict_types=1);

/**
 * OpenID Connect Core 1.0 §2 (auth_time) + Back-Channel Logout 1.0 §2.1 (sid)
 */

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Lock\Server\Sessions\Models\OidcSession;
use Lock\Server\Sessions\OidcSessionRepository;
use Workbench\App\Models\User;

it('records auth_time and a sid without starting the session store on an identity-guard login', function (): void {
    $session = app('session.store');
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'email_verified_at' => now(), 'password' => 'x']);

    expect($session->isStarted())->toBeFalse();

    Auth::guard((string) config('oidc.auth.guard', 'identity'))->login($user);

    expect($session->get('oidc.auth_time'))->toBeInt()
        ->and($session->get('oidc.sid'))->toBeString()
        ->and($session->isStarted())->toBeFalse()
        ->and(OidcSession::query()->where('user_id', (string) $user->id)->count())->toBe(1);
});

it('records nothing for one-off authentication or logins on another guard', function (): void {
    $session = app('session.store');
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'email_verified_at' => now(), 'password' => 'x']);

    Auth::guard((string) config('oidc.auth.guard', 'identity'))->onceUsingId($user->id);
    Auth::guard('web')->login($user);

    expect($session->has('oidc.auth_time'))->toBeFalse()
        ->and($session->has('oidc.sid'))->toBeFalse()
        ->and(OidcSession::query()->count())->toBe(0);
});

it('ties the OIDC session to the browser session the login ended in', function (): void {
    User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('password')]);

    $this->post(route('identity.login.store'), ['email' => 'm@example.com', 'password' => 'password'])->assertRedirect();

    expect(app(OidcSessionRepository::class)->findByBrowserSession(session()->getId())?->id)->toBe(session('oidc.sid'));
});
