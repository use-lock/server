<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Hash;
use Workbench\App\Models\User;

it('rejects password confirmation with the wrong password', function (): void {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('password')]);

    $this->actingAs($user, 'identity')
        ->from('/auth/user/confirm-password')
        ->post(route('identity.password.confirm.store'), ['password' => 'wrong-password'])
        ->assertRedirect('/auth/user/confirm-password')
        ->assertSessionHasErrors('password');

    expect(session()->has('auth.password_confirmed_at'))->toBeFalse();
});

it('reports the confirmation status through the status endpoint', function (): void {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('password')]);

    $this->actingAs($user, 'identity')
        ->getJson(route('identity.password.confirmation'))
        ->assertOk()
        ->assertJson(['confirmed' => false]);

    $this->actingAs($user, 'identity')
        ->post(route('identity.password.confirm.store'), ['password' => 'password'])
        ->assertRedirect('/dashboard')
        ->assertSessionHas('auth.password_confirmed_at');

    $this->actingAs($user, 'identity')
        ->getJson(route('identity.password.confirmation'))
        ->assertOk()
        ->assertJson(['confirmed' => true]);
});

it('treats an elapsed confirmation as unconfirmed', function (): void {
    config()->set('auth.password_timeout', 900);

    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => Hash::make('password')]);

    $this->actingAs($user, 'identity')
        ->withSession(['auth.password_confirmed_at' => time() - 1000])
        ->getJson(route('identity.password.confirmation'))
        ->assertOk()
        ->assertJson(['confirmed' => false]);
});
