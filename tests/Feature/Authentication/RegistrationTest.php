<?php

declare(strict_types=1);

use Illuminate\Auth\Events\Registered;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Workbench\App\Models\User;

it('registers a user through the package action seam and logs them in', function (): void {
    Event::fake([Registered::class]);

    createUsersUsing(fn (array $input): Authenticatable => User::create([
        'name' => $input['name'],
        'email' => $input['email'],
        'password' => Hash::make($input['password']),
    ]));

    $response = $this->from('/auth/register')->post(route('identity.register.store'), [
        'name' => 'M',
        'email' => 'MixedCase@Example.com',
        'password' => 'password',
        'password_confirmation' => 'password',
    ]);

    $user = User::where('email', 'mixedcase@example.com')->firstOrFail();

    $response->assertRedirect('/dashboard');
    $this->assertAuthenticatedAs($user, 'identity');
    expect(session()->get('oidc.amr'))->toBe(['pwd']);
    Event::assertDispatched(Registered::class, fn (Registered $event): bool => $event->user->is($user));
});

it('returns 404 from the register endpoint when no create user action is registered', function (): void {
    $this->postJson(route('identity.register.store'), [
        'name' => 'M',
        'email' => 'm@example.com',
        'password' => 'password',
        'password_confirmation' => 'password',
    ])->assertNotFound();

    $this->assertGuest('identity');
    expect(User::query()->count())->toBe(0);
});

it('returns the JSON success response after registration', function (): void {
    createUsersUsing(fn (array $input): Authenticatable => User::create([
        'name' => $input['name'],
        'email' => $input['email'],
        'password' => Hash::make($input['password']),
    ]));

    $this->postJson(route('identity.register.store'), [
        'name' => 'M',
        'email' => 'm@example.com',
        'password' => 'password',
        'password_confirmation' => 'password',
    ])->assertCreated();

    $this->assertAuthenticated('identity');
});
