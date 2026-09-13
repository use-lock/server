<?php

declare(strict_types=1);

use Lock\Server\Authentication\Context\LoginState;
use Lock\Server\Protocol\Authorize\AuthorizeRequestSession;
use Lock\Server\Sessions\OidcSessionState;
use Lock\Server\Shared\Audit\SessionContext;
use Lock\Server\Shared\Authentication\LoginContext;
use Lock\Server\Shared\Authentication\PendingAuthorization;

it('preserves the login snapshot after the login state is changed and cleared', function (): void {
    $this->withSession([]);
    $state = app(LoginState::class);
    $state->start('pwd');
    $state->add('otp', 'pwd');
    $state->putClaims(['department' => 'engineering'], ['permissions' => ['read']]);
    $state->putRequestedActions(['verify-email']);

    $snapshot = app(LoginContext::class)->snapshot();

    $state->start('social');
    $state->putClaims(['department' => 'sales'], []);
    $state->forget();

    expect($snapshot->amr)->toBe(['pwd', 'otp'])
        ->and($snapshot->idTokenClaims)->toBe(['department' => 'engineering'])
        ->and($snapshot->accessTokenClaims)->toBe(['permissions' => ['read']])
        ->and(app(LoginContext::class)->snapshot()->amr)->toBe([])
        ->and(app(LoginContext::class)->snapshot()->idTokenClaims)->toBe([])
        ->and(app(LoginContext::class)->snapshot()->accessTokenClaims)->toBe([])
        ->and($state->requestedActions())->toBe([]);
});

it('clears a login attempt without discarding the OIDC session or authorization requirements', function (): void {
    $this->withSession([]);
    $request = request();
    $request->setLaravelSession(app('session.store'));
    $session = app(OidcSessionState::class);
    $session->startOidcSession('session-id');
    $session->putAuthTime(1234);
    app(AuthorizeRequestSession::class)->rememberAcrValues($request, ['urn:example:mfa']);
    $state = app(LoginState::class);
    $state->start('pwd');
    $state->forget();

    expect(app(SessionContext::class)->sid())->toBe('session-id')
        ->and($session->authTime())->toBe(1234)
        ->and(app(PendingAuthorization::class)->acrValues($request))->toBe(['urn:example:mfa']);

    app(AuthorizeRequestSession::class)->rememberAcrValues($request, []);

    expect(app(PendingAuthorization::class)->acrValues($request))->toBe([]);
});
