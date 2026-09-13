<?php

declare(strict_types=1);

use Illuminate\Database\Eloquent\JsonEncodingException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Lock\Server\Clients\Models\Client;
use Lock\Server\Shared\Audit\AuditEventType;
use Lock\Server\Shared\Audit\AuditRecord;
use Lock\Server\Tokens\DirectAccessTokenIssuer;
use Lock\Server\Tokens\Exceptions\TokenIssuanceDeniedException;
use Lock\Server\Tokens\Guard\CurrentAccessToken;
use Lock\Server\Tokens\Models\AccessToken;
use Lock\Server\Tokens\Pipeline\AccessTokenApi;
use Lock\Server\Tokens\Pipeline\AccessTokenPipeline;
use Lock\Server\Tokens\Pipeline\DirectAccessTokenEvent;
use Workbench\App\Models\User;

beforeEach(function (): void {
    $this->user = User::factory()->create();
    $this->client = Client::factory()->create(['grant_types' => ['direct_access']]);
});

it('runs the direct-access trigger once and applies its claims to the issued token', function (): void {
    $triggerCount = 0;

    app(AccessTokenPipeline::class)->register('direct_access', function (DirectAccessTokenEvent $event, AccessTokenApi $api) use (&$triggerCount): void {
        $triggerCount++;

        expect($event->user->getAuthIdentifier())->toBe($this->user->id)
            ->and($event->scopes)->toBe(['openid']);

        $api->setAccessTokenClaim('project_id', 'p-2');
    });

    $claims = parseAccessToken(app(DirectAccessTokenIssuer::class)->issue($this->user, $this->client->snapshot(), 'cli', ['openid'])->accessToken)->claims();

    expect($claims->get('sub'))->toBe((string) $this->user->id)
        ->and($claims->get('project_id'))->toBe('p-2')
        ->and($triggerCount)->toBe(1);
});

it('stores the context a token is created with and serves it to the bearer guard', function (): void {
    Route::middleware('auth:oidc')->get('/context', fn (Request $request): array => $request->user()->currentAccessToken()?->context() ?? []);
    app(AccessTokenPipeline::class)->register('direct_access', function (DirectAccessTokenEvent $event): void {
        expect($event->context)->toBe(['tenant_id' => 't-1']);
    });

    $result = app(DirectAccessTokenIssuer::class)->issue($this->user, $this->client->snapshot(), 'cli', ['openid'], ['tenant_id' => 't-1']);

    expect($result->token->context)->toBe(['tenant_id' => 't-1']);

    $this->withToken($result->accessToken)->getJson('/context')
        ->assertOk()
        ->assertExactJson(['tenant_id' => 't-1']);
});

it('leaves the context empty when a token is created without one', function (): void {
    $result = app(DirectAccessTokenIssuer::class)->issue($this->user, $this->client->snapshot(), 'cli', ['openid']);

    expect($result->token->context)->toBeNull()
        ->and(new CurrentAccessToken($result->token)->context())->toBe([]);
});

it('denies issuance before persisting when a trigger denies', function (): void {
    $sink = fakeAudit();
    app(AccessTokenPipeline::class)->register('direct_access', fn (DirectAccessTokenEvent $event, AccessTokenApi $api) => $api->deny('direct_access_blocked'));

    expect(fn () => app(DirectAccessTokenIssuer::class)->issue($this->user, $this->client->snapshot(), 'cli', ['openid']))->toThrow(TokenIssuanceDeniedException::class)
        ->and(AccessToken::query()->count())->toBe(0);
    $sink->assertRecorded(AuditEventType::TokenIssuanceFailed, fn (AuditRecord $record): bool => $record->context['grant_type'] === 'direct_access'
        && $record->context['reason'] === 'pipeline_denied'
        && $record->context['deny_reason'] === 'direct_access_blocked');
});

it('issues against the explicitly selected client using its current scope assignments', function (): void {
    Client::factory()->create(['grant_types' => ['direct_access']]);
    $snapshot = $this->client->snapshot();
    $this->client->update(['default_scopes' => ['email'], 'optional_scopes' => ['profile']]);

    $result = app(DirectAccessTokenIssuer::class)->issue($this->user, $snapshot, 'automation', ['profile', 'openid']);

    expect($result->token->client_id)->toBe($this->client->id)
        ->and($result->token->name)->toBe('automation')
        ->and($result->token->scopes)->toBe(['profile', 'email']);
    expect(parseAccessToken($result->accessToken)->claims()->get('client_id'))->toBe($this->client->client_id);
});

it('denies an ineligible client before running hooks or persisting tokens', function (string $state): void {
    $sink = fakeAudit();
    $snapshot = $this->client->snapshot();

    match ($state) {
        'revoked' => $this->client->update(['revoked_at' => now()]),
        'disabled' => $this->client->update(['grant_types' => ['authorization_code']]),
        'deleted' => $this->client->delete(),
        'other realm' => config(['oidc.realm' => 'another-realm']),
        default => throw new LogicException('Unknown client state.'),
    };

    $called = false;
    app(AccessTokenPipeline::class)->register('direct_access', function () use (&$called): void {
        $called = true;
    });

    expect(fn () => app(DirectAccessTokenIssuer::class)->issue($this->user, $snapshot, 'cli'))
        ->toThrow(TokenIssuanceDeniedException::class);
    expect($called)->toBeFalse();
    expect(AccessToken::query()->count())->toBe(0);
    $sink->assertRecorded(AuditEventType::TokenIssuanceFailed, fn (AuditRecord $record): bool => $record->context['grant_type'] === 'direct_access'
        && $record->context['reason'] === 'client_ineligible'
        && $record->clientId === $snapshot->clientId);
})->with(['revoked', 'disabled', 'deleted', 'other realm']);

it('keeps direct issuance unavailable through the token endpoint', function (): void {
    $this->postJson('/oauth/token', [
        'grant_type' => 'direct_access',
        'client_id' => $this->client->client_id,
        'client_secret' => $this->client->secret,
    ])->assertStatus(400)->assertJsonPath('error', 'unsupported_grant_type');
});

it('lists and revokes only the current realm tokens belonging to the user', function (): void {
    $current = app(DirectAccessTokenIssuer::class)->issue($this->user, $this->client->snapshot(), 'current');
    $otherUser = User::factory()->create();
    $unrelated = app(DirectAccessTokenIssuer::class)->issue($otherUser, $this->client->snapshot(), 'unrelated');

    config(['oidc.realm' => 'another-realm']);
    generateRealmSigningKey();
    $otherClient = Client::factory()->create(['grant_types' => ['direct_access']]);
    $other = app(DirectAccessTokenIssuer::class)->issue($this->user, $otherClient->snapshot(), 'other');

    expect($this->user->tokens()->pluck('id')->all())->toBe([$other->token->id]);
    config(['oidc.realm' => 'default']);
    expect($this->user->tokens()->pluck('id')->all())->toBe([$current->token->id]);

    $this->user->tokens()->update(['revoked_at' => now()]);

    expect($current->token->refresh()->isRevoked())->toBeTrue();
    expect($other->token->refresh()->isRevoked())->toBeFalse();
    expect($unrelated->token->refresh()->isRevoked())->toBeFalse();
});

it('rolls back issuance when token context cannot be persisted', function (): void {
    expect(fn () => app(DirectAccessTokenIssuer::class)->issue($this->user, $this->client->snapshot(), 'cli', context: ['invalid' => "\xB1"]))
        ->toThrow(JsonEncodingException::class);

    expect(AccessToken::query()->count())->toBe(0);
});

it('rejects a directly issued bearer token after revocation', function (): void {
    Route::middleware('auth:oidc')->get('/direct-token', fn (Request $request): array => ['user' => $request->user()->getAuthIdentifier()]);
    $result = app(DirectAccessTokenIssuer::class)->issue($this->user, $this->client->snapshot(), 'cli');

    $this->withToken($result->accessToken)->getJson('/direct-token')->assertOk()->assertJsonPath('user', $this->user->id);

    expect(new CurrentAccessToken($result->token)->revoke())->toBeTrue();
    app('auth')->forgetGuards();

    $this->withToken($result->accessToken)->getJson('/direct-token')->assertUnauthorized();
});
