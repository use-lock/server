<?php

declare(strict_types=1);

use Illuminate\Auth\Events\Verified;
use Illuminate\Auth\Notifications\VerifyEmail;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\URL;
use Workbench\App\Models\User;

it('redirects verified users away from the verification notice', function (): void {
    $user = User::create([
        'name' => 'M',
        'email' => 'm@example.com',
        'email_verified_at' => now(),
        'password' => 'secret',
    ]);

    $this->actingAs($user, 'identity')->get('/auth/email/verify')->assertRedirect('/dashboard');
});

it('verifies a signed email verification URL and fires the event', function (): void {
    Event::fake([Verified::class]);

    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);

    $url = URL::temporarySignedRoute('identity.verification.verify', now()->addMinutes(60), [
        'id' => $user->getKey(),
        'hash' => sha1($user->getEmailForVerification()),
    ]);

    $this->actingAs($user, 'identity')->get($url)->assertRedirect('/dashboard?verified=1');

    expect($user->fresh()->hasVerifiedEmail())->toBeTrue();
    Event::assertDispatched(Verified::class);
});

it('resends the email verification notification', function (): void {
    Notification::fake();

    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);

    $this->actingAs($user, 'identity')
        ->from('/auth/email/verify')
        ->post('/auth/email/verification-notification')
        ->assertRedirect('/auth/email/verify')
        ->assertSessionHas('status', 'verification-link-sent');

    Notification::assertSentTo(
        $user,
        VerifyEmail::class,
        fn (VerifyEmail $notification): bool => str_contains(
            (string) $notification->toMail($user)->actionUrl,
            '/auth/email/verify/',
        ),
    );
});
