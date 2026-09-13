<?php
declare(strict_types=1);

use Laravel\Passkeys\Passkey;
use Lock\Server\Credentials\Ui\Actions\RevokeFactorAction;
use Lock\Server\Credentials\Ui\Tables\TwoFactorMethodsTable;
use Workbench\App\Models\User;

function createPasskey(User $user, string $name = 'My passkey'): Passkey
{
    return $user->passkeys()->create([
        'name' => $name,
        'credential_id' => 'cred-'.fake()->unique()->uuid(),
        'credential' => ['type' => 'public-key'],
    ]);
}

test('users can revoke their own passkey through the methods table action', function (): void {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);
    $passkey = createPasskey($user);

    $this->actingAs($user)
        ->callAction(RevokeFactorAction::class, context: ['provider' => 'webauthn', 'enrollment' => (string) $passkey->id])
        ->assertOk()
        ->assertJsonFragment(['type' => 'reload-component', 'component' => 'oidc.two-factor.methods']);

    expect($user->passkeys()->whereKey($passkey->id)->exists())->toBeFalse();
});

test('users cannot revoke another users passkey', function (): void {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);
    $other = User::create(['name' => 'O', 'email' => 'o@example.com', 'password' => 'secret']);
    $passkey = createPasskey($other);

    $this->actingAs($user)
        ->callDeniedAction(RevokeFactorAction::class, context: ['provider' => 'webauthn', 'enrollment' => (string) $passkey->id])
        ->assertForbidden();

    expect($other->passkeys()->whereKey($passkey->id)->exists())->toBeTrue();
});

test('the methods table lists only the authenticated users passkeys', function (): void {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'secret']);
    $other = User::create(['name' => 'O', 'email' => 'o@example.com', 'password' => 'secret']);
    createPasskey($user, 'My MacBook');
    createPasskey($other, 'Other Device');

    $this->actingAs($user)
        ->loadTable(TwoFactorMethodsTable::class)
        ->assertOk()
        ->assertSee('My MacBook')
        ->assertDontSee('Other Device');
});
