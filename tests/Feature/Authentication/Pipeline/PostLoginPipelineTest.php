<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Lock\Server\Authentication\Pipeline\LoginApi;
use Lock\Server\Authentication\Pipeline\LoginEvent;
use Lock\Server\Authentication\Pipeline\NullDeviceRecognizer;
use Lock\Server\Authentication\Pipeline\PostLoginPipeline;
use Workbench\App\Models\User;

/** @param list<string> $amr */
function makeLoginEvent(array $amr = ['pwd']): LoginEvent
{
    $user = User::create(['name' => 'M', 'email' => 'm'.uniqid().'@example.com', 'password' => 'x']);

    return new LoginEvent(
        user: $user, client: null, scopes: ['openid'], requestedAcrValues: [],
        ip: null, userAgent: null, amr: $amr, authTime: null,
        recognizer: new NullDeviceRecognizer, request: Request::create('/', 'POST'),
    );
}

it('accumulates the decisions of every registered hook on one api', function (): void {
    $pipeline = new PostLoginPipeline;
    $pipeline->register(fn (LoginEvent $e, LoginApi $api) => $api->setIdTokenClaim('a', 1));
    $pipeline->register(fn (LoginEvent $e, LoginApi $api) => $api->requireMfa());

    $api = $pipeline->run(makeLoginEvent());

    expect($api->idTokenClaims())->toBe(['a' => 1])
        ->and($api->mfaRequired())->toBeTrue()
        ->and($api->isDenied())->toBeFalse();
});

it('fails closed and skips the remaining hooks when a hook throws', function (): void {
    $pipeline = new PostLoginPipeline;
    $pipeline->register(function (): void {
        throw new RuntimeException('boom');
    });
    $pipeline->register(fn (LoginEvent $e, LoginApi $api) => $api->setIdTokenClaim('never', 1));

    $api = $pipeline->run(makeLoginEvent());

    expect($api->isDenied())->toBeTrue()
        ->and($api->denyReason())->toBe('post_login_error')
        ->and($api->idTokenClaims())->toBe([]);
});

it('refuses protected id_token and access-token claim names from hooks', function (): void {
    $api = new LoginApi;

    $api->setIdTokenClaim('groups', ['admin']);
    $api->setIdTokenClaim('sub', 'attacker');
    $api->setIdTokenClaim('amr', ['forged']);
    $api->setIdTokenClaim('sid', 'forged');

    $api->setAccessTokenClaim('tier', 'gold');

    $api->setAccessTokenClaim('scope', 'forged');

    expect($api->idTokenClaims())->toBe(['groups' => ['admin']])
        ->and($api->accessTokenClaims())->toBe(['tier' => 'gold']);
});
