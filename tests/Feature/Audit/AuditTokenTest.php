<?php

declare(strict_types=1);

use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Foundation\Http\Middleware\ValidateCsrfToken;
use Lock\Server\Clients\ClientRepository;
use Lock\Server\Sessions\OidcSessionRepository;
use Lock\Server\Shared\Audit\AuditEventType;
use Lock\Server\Shared\Audit\AuditRecord;
use Lock\Server\Support\Testing\InteractsWithOidc;
use Lock\Server\Tests\FeatureTestCase;
use Lock\Server\Tokens\DirectAccessTokenIssuer;
use Workbench\App\Models\User;

uses(InteractsWithOidc::class);

beforeEach(function (): void {
    $this->withoutMiddleware([ValidateCsrfToken::class, PreventRequestForgery::class]);
    fakeConsentViewUsing(fn (array $parameters) => response()->json([
        'authToken' => $parameters['authToken'],
    ]));

    $this->user = User::create(['name' => 'M', 'email' => 'audit@example.com', 'email_verified_at' => now(), 'password' => 'x']);
    $this->client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/callback']);
});

it('audits consent approval and token issuance through the code flow', function (): void {
    $sink = fakeAudit();

    $sid = app(OidcSessionRepository::class)->start((string) $this->user->id);
    $this->actingAsIdentity($this->user, authTime: time() - 60)->withSession(['oidc.sid' => $sid]);
    $this->authorizeAndApprove($this->user, $this->client, scopes: 'openid')->response->assertOk();

    $sink->assertRecorded(AuditEventType::ConsentApproved, fn (AuditRecord $record): bool => $record->clientId === (string) $this->client->id
        && $record->userId === (string) $this->user->id
        && $record->context['scopes'] === ['openid']);

    $issued = $sink->assertRecorded(AuditEventType::TokenIssued, fn (AuditRecord $record): bool => $record->context['grant_type'] === 'authorization_code');

    expect($issued->userId)->toBe((string) $this->user->id)
        ->and($issued->clientId)->toBe((string) $this->client->id)
        ->and($issued->sid)->not->toBeNull()
        ->and($issued->context['jti'])->toBeString()
        ->and($issued->context['scopes'])->toBe(['openid']);
});

it('audits a denied consent', function (): void {
    $sink = fakeAudit();
    $pkce = $this->pkce();

    $view = $this->actingAsIdentity($this->user, authTime: time() - 60)
        ->get('/oauth/authorize?'.http_build_query([
            'client_id' => $this->client->id,
            'redirect_uri' => 'https://rp.test/callback',
            'response_type' => 'code',
            'scope' => 'openid',
            'state' => 'st4te',
            'code_challenge' => $pkce->challenge,
            'code_challenge_method' => 'S256',
        ]))
        ->assertOk();

    $this->delete(route('oidc.deny'), ['auth_token' => $view->json('authToken')])
        ->assertRedirect();

    $sink->assertRecorded(AuditEventType::ConsentDenied, fn (AuditRecord $record): bool => $record->clientId === (string) $this->client->id
        && $record->userId === (string) $this->user->id);
    $sink->assertNotRecorded(AuditEventType::ConsentApproved);
    $sink->assertNotRecorded(AuditEventType::TokenIssued);
});

it('audits a refresh token grant as token issuance', function (): void {
    $sid = app(OidcSessionRepository::class)->start((string) $this->user->id);
    $result = $this->actingAsIdentity($this->user, authTime: time() - 60)
        ->withSession(['oidc.sid' => $sid])
        ->authorizeAndApprove($this->user, $this->client, scopes: 'openid');

    $sink = fakeAudit();

    $this->post('/oauth/token', [
        'grant_type' => 'refresh_token',
        'refresh_token' => $result->response->json('refresh_token'),
        'client_id' => $this->client->id,
        'client_secret' => $this->client->secret,
    ])->assertOk();

    $sink->assertRecorded(AuditEventType::TokenIssued, fn (AuditRecord $record): bool => $record->context['grant_type'] === 'refresh_token'
        && $record->userId === (string) $this->user->id
        && $record->sid !== null);
});

it('audits a refresh denied after the session ended', function (): void {
    $sid = app(OidcSessionRepository::class)->start((string) $this->user->id);
    $result = $this->actingAsIdentity($this->user, authTime: time() - 60)
        ->withSession(['oidc.sid' => $sid])
        ->authorizeAndApprove($this->user, $this->client, scopes: 'openid');

    $sink = fakeAudit();
    app(OidcSessionRepository::class)->revoke($sid);

    $this->post('/oauth/token', [
        'grant_type' => 'refresh_token',
        'refresh_token' => $result->response->json('refresh_token'),
        'client_id' => $this->client->id,
        'client_secret' => $this->client->secret,
    ])->assertStatus(400);

    $sink->assertRecorded(AuditEventType::TokenIssuanceFailed, fn (AuditRecord $record): bool => $record->context['grant_type'] === 'refresh_token'
        && $record->context['reason'] === 'session_ended');
    $sink->assertNotRecorded(AuditEventType::TokenIssued);
});

it('audits a client credentials token issuance', function (): void {
    $sink = fakeAudit();
    $client = app(ClientRepository::class)->createClientCredentialsGrantClient('M2M');

    $this->post('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $client->id,
        'client_secret' => $client->secret,
        'scope' => '',
    ])->assertOk();

    $sink->assertRecorded(AuditEventType::TokenIssued, fn (AuditRecord $record): bool => $record->context['grant_type'] === 'client_credentials'
        && $record->clientId === (string) $client->id
        && $record->userId === null);
});

it('audits a token exchange and its failure paths', function (): void {
    config(['oidc.scopes' => ['openid' => 'Authenticate', 'orders:read' => 'Read orders']]);
    $this->client->forceFill([
        'grant_types' => [...(array) $this->client->getAttribute('grant_types'), FeatureTestCase::TOKEN_EXCHANGE_GRANT],
        'allowed_exchange_audiences' => ['https://api.internal/orders'],
    ])->save();

    $sink = fakeAudit();
    $subject = mintExchangeSubjectToken((string) $this->client->id, (string) $this->user->id, ['openid', 'orders:read']);

    $this->post('/oauth/token', [
        'grant_type' => FeatureTestCase::TOKEN_EXCHANGE_GRANT,
        'client_id' => $this->client->id,
        'client_secret' => $this->client->secret,
        'subject_token' => $subject,
        'subject_token_type' => 'urn:ietf:params:oauth:token-type:access_token',
        'audience' => 'https://api.internal/orders',
        'scope' => 'orders:read',
    ])->assertOk();

    $sink->assertRecorded(AuditEventType::TokenIssued, fn (AuditRecord $record): bool => $record->context['grant_type'] === 'urn:ietf:params:oauth:grant-type:token-exchange'
        && $record->userId === (string) $this->user->id
        && $record->context['audiences'] === ['https://api.internal/orders']);

    $revoked = mintExchangeSubjectToken((string) $this->client->id, (string) $this->user->id, ['openid'], revoked: true);

    $this->post('/oauth/token', [
        'grant_type' => FeatureTestCase::TOKEN_EXCHANGE_GRANT,
        'client_id' => $this->client->id,
        'client_secret' => $this->client->secret,
        'subject_token' => $revoked,
        'subject_token_type' => 'urn:ietf:params:oauth:token-type:access_token',
        'audience' => 'https://api.internal/orders',
    ])->assertStatus(400);

    $sink->assertRecorded(AuditEventType::TokenIssuanceFailed, fn (AuditRecord $record): bool => $record->context['reason'] === 'subject_token_invalid'
        && $record->clientId === (string) $this->client->id);
});

it('audits direct access token issuance', function (): void {
    $sink = fakeAudit();
    $this->client->update(['grant_types' => ['direct_access']]);

    $result = app(DirectAccessTokenIssuer::class)->issue($this->user, $this->client->snapshot(), 'cli', ['openid']);

    $token = $result->token;

    $sink->assertRecorded(AuditEventType::TokenIssued, fn (AuditRecord $record): bool => $record->context['grant_type'] === 'direct_access'
        && $record->userId === (string) $this->user->id
        && $record->context['jti'] === (string) $token->getKey());
});

it('audits an access token revocation', function (): void {
    $this->client->update(['grant_types' => ['direct_access']]);
    $result = app(DirectAccessTokenIssuer::class)->issue($this->user, $this->client->snapshot(), 't', ['openid']);
    $token = $result->token;

    $sink = fakeAudit();

    $this->postJson('/oauth/revoke', [
        'client_id' => $this->client->id,
        'client_secret' => $this->client->secret,
        'token' => $result->accessToken,
    ])->assertOk();

    $sink->assertRecorded(AuditEventType::TokenRevoked, fn (AuditRecord $record): bool => $record->clientId === (string) $this->client->id
        && $record->context['token_type'] === 'access_token'
        && $record->context['jti'] === (string) $token->getKey());
});

it('audits a failed client authentication at the introspection endpoint', function (): void {
    $sink = fakeAudit();

    $this->postJson('/oauth/introspect', [
        'client_id' => $this->client->id,
        'client_secret' => 'wrong-secret',
        'token' => 'irrelevant',
    ])->assertStatus(401);

    $sink->assertRecorded(AuditEventType::ClientAuthenticationFailed, fn (AuditRecord $record): bool => $record->clientId === (string) $this->client->id
        && $record->context['endpoint'] === 'oauth/introspect');
});

it('audits a failed client authentication at the token endpoint', function (): void {
    $sink = fakeAudit();
    $client = app(ClientRepository::class)->createClientCredentialsGrantClient('M2M');

    $this->post('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $client->id,
        'client_secret' => 'wrong-secret',
        'scope' => '',
    ])->assertStatus(401);

    $sink->assertRecorded(AuditEventType::ClientAuthenticationFailed, fn (AuditRecord $record): bool => $record->clientId === (string) $client->id
        && $record->context['endpoint'] === 'oauth/token');
});
