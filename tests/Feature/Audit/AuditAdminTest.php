<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Lock\Server\Shared\Audit\AuditEventType;
use Lock\Server\Shared\Audit\AuditRecord;
use Lock\Server\Shared\Clients\ClientProvisioner;
use Lock\Server\Shared\Realms\CurrentRealm;
use Lock\Server\Shared\Realms\RealmResolver;

it('audits a dynamic client registration', function (): void {
    config(['oidc.clients.registration.enabled' => true]);
    reloadOidcRoutes();
    $sink = fakeAudit();

    $response = $this->postJson('/oauth/register', [
        'client_name' => 'Agent',
        'redirect_uris' => ['https://mcp.test/callback'],
    ])->assertCreated();

    $sink->assertRecorded(AuditEventType::ClientRegistered, fn (AuditRecord $record): bool => $record->clientId === $response->json('client_id')
        && $record->context['client_name'] === 'Agent'
        && $record->context['redirect_uris'] === ['https://mcp.test/callback']);
});

it('audits first party client provisioning and secret rotation', function (): void {
    $sink = fakeAudit();

    $result = DB::transaction(function () use ($sink) {
        $result = CurrentRealm::runAs('other', fn () => app(ClientProvisioner::class)->provision('First-Party App', ['https://app.test/callback']));
        expect(app(RealmResolver::class)->current()->identifier())->not->toBe('other');
        $sink->assertNotRecorded(AuditEventType::ClientProvisioned);

        return $result;
    });

    $sink->assertRecorded(AuditEventType::ClientProvisioned, fn (AuditRecord $record): bool => $record->clientId === $result->client->clientId
        && $record->realm === 'other'
        && $record->context['created'] === true
        && $record->context['secret_rotated'] === false);

    CurrentRealm::runAs('other', fn () => app(ClientProvisioner::class)->provision(
        'First-Party App',
        ['https://app.test/callback'],
        rotateSecret: true,
    ));

    $sink->assertRecorded(AuditEventType::ClientProvisioned, fn (AuditRecord $record): bool => $record->context['secret_rotated'] === true
        && $record->context['created'] === false);
});

it('audits a key rotation but not a skipped one', function (): void {
    $sink = fakeAudit();

    $this->artisan('oidc:rotate-keys', ['--if-missing' => true])->assertSuccessful();

    $sink->assertNotRecorded(AuditEventType::KeysRotated);

    DB::transaction(function () use ($sink): void {
        CurrentRealm::runAs('other', function (): void {
            $this->artisan('oidc:rotate-keys', ['--force' => true])->assertSuccessful();
        });

        expect(app(RealmResolver::class)->current()->identifier())->not->toBe('other');
        $sink->assertNotRecorded(AuditEventType::KeysRotated);
    });

    $record = $sink->assertRecorded(AuditEventType::KeysRotated);

    expect($record->realm)->toBe('other')
        ->and($record->context['kid'])->toBeString()
        ->and($record->context)->not->toHaveKeys(['private_key', 'public_key']);
});
