<?php

declare(strict_types=1);

/**
 * RFC 8176 (amr value pwd)
 */

use Illuminate\Support\Facades\Hash;
use Workbench\App\Models\User;

it('logs a user in with canonicalized credentials on the identity guard only and redirects home', function (): void {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('password')]);

    $response = $this->from('/auth/login')->post(route('identity.login.store'), [
        'email' => 'M@Example.com',
        'password' => 'password',
    ]);

    $response->assertRedirect('/dashboard');
    $this->assertAuthenticatedAs($user, 'identity');
    $this->assertGuest('web');
    expect(session()->get('oidc.amr'))->toBe(['pwd']);
});

it('returns the JSON success response after login', function (): void {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('password')]);

    $this->postJson(route('identity.login.store'), [
        'email' => 'm@example.com',
        'password' => 'password',
    ])->assertOk();

    $this->assertAuthenticatedAs($user, 'identity');
});

it('rejects invalid credentials with a validation error', function (): void {
    User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('password')]);

    $this->from('/auth/login')
        ->post(route('identity.login.store'), ['email' => 'm@example.com', 'password' => 'wrong-password'])
        ->assertRedirect('/auth/login')
        ->assertSessionHasErrors('email');

    $this->assertGuest('identity');
});

it('sets a remember cookie when remember is requested', function (): void {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('password')]);

    $response = $this->post(route('identity.login.store'), [
        'email' => 'm@example.com',
        'password' => 'password',
        'remember' => true,
    ]);

    $this->assertAuthenticatedAs($user, 'identity');
    $response->assertCookie(auth()->guard('identity')->getRecallerName());
});

it('throttles repeated login attempts', function (): void {
    User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('password')]);

    foreach (range(1, 5) as $ignored) {
        $this->post(route('identity.login.store'), ['email' => 'm@example.com', 'password' => 'wrong-password']);
    }

    $this->post(route('identity.login.store'), ['email' => 'm@example.com', 'password' => 'wrong-password'])
        ->assertStatus(429);

    $this->assertGuest('identity');
});

it('redirects identity-protected routes to the identity login even for a web-guard session', function (): void {
    config(['oidc.login.route' => 'identity.login']);
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);

    $this->actingAs($user, 'web')
        ->get('/auth/user/confirmed-password-status')
        ->assertRedirect('/auth/login');

    $this->assertAuthenticatedAs($user, 'web');
    $this->assertGuest('identity');
});
