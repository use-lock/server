<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Exceptions;
use Lock\Server\Audit\Contracts\AuditSink;
use Lock\Server\Authentication\Events\LoggedOut;
use Lock\Server\Authentication\Events\LoginFailed;
use Lock\Server\Authentication\Events\LoginSucceeded;
use Lock\Server\Authentication\Events\PasswordChanged;
use Lock\Server\Shared\Audit\AuditEvent;
use Lock\Server\Shared\Audit\AuditEventType;
use Lock\Server\Shared\Audit\AuditRecord;
use Lock\Server\Shared\Context\OidcContext;
use Lock\Server\Shared\Realms\RealmResolver;
use Lock\Server\Tokens\Events\TokenIssued;

enum HostAuditType: string
{
    case ExportDownloaded = 'app.export.downloaded';
}

it('records a dispatched audit event through the configured sink', function (): void {
    $sink = fakeAudit();

    event(new LoginSucceeded('42', ['pwd']));

    $record = $sink->assertRecorded(AuditEventType::LoginSucceeded);

    expect($record->userId)->toBe('42')
        ->and($record->context)->toBe(['amr' => ['pwd']])
        ->and($record->failure)->toBeFalse()
        ->and($record->category())->toBe('auth');
});

it('records any event implementing the audit contract, including host-defined ones', function (): void {
    $sink = fakeAudit();

    event(new class implements AuditEvent
    {
        public BackedEnum $type { get => HostAuditType::ExportDownloaded; }

        public function auditRecord(): AuditRecord
        {
            return new AuditRecord($this->type, userId: '7', context: ['file' => 'report.csv']);
        }
    });

    $record = $sink->assertRecorded(HostAuditType::ExportDownloaded);

    expect($record->context)->toBe(['file' => 'report.csv'])
        ->and($record->category())->toBe('app');
});

it('stops recording when audit logging is disabled', function (): void {
    config()->set('oidc.audit.enabled', false);
    $sink = fakeAudit();

    event(new LoginSucceeded('42', ['pwd']));

    $sink->assertNothingRecorded();
});

it('enriches records with request ip and truncated user agent', function (): void {
    $sink = fakeAudit();
    app()->instance('request', Request::create(
        '/login', 'POST', [], [], [],
        ['REMOTE_ADDR' => '10.0.0.1', 'HTTP_USER_AGENT' => str_repeat('a', 300)],
    ));

    event(new LoginFailed('pwd', 'invalid_credentials'));

    $record = $sink->assertRecorded(AuditEventType::LoginFailed);

    expect($record->ip)->toBe('10.0.0.1')
        ->and($record->userAgent)->toBe(str_repeat('a', 255))
        ->and($record->failure)->toBeTrue();
});

it('falls back to the session sid unless the event carries one', function (): void {
    $sink = fakeAudit();
    $this->session(['oidc.sid' => 'sid-123']);

    event(new LoggedOut('42'));
    event(new TokenIssued('default', 'refresh_token', 'jti-1', [], sid: 'sid-456'));

    expect($sink->assertRecorded(AuditEventType::LoggedOut)->sid)->toBe('sid-123')
        ->and($sink->assertRecorded(AuditEventType::TokenIssued)->sid)->toBe('sid-456');
});

it('reports and swallows sink failures', function (): void {
    Exceptions::fake();
    app()->instance(AuditSink::class, new class implements AuditSink
    {
        public function record(AuditRecord $record): void
        {
            expect($record->realm)->toBe('other')
                ->and(app(RealmResolver::class)->current()->identifier())->toBe('other')
                ->and(OidcContext::realm())->toBe('other');

            throw new RuntimeException('sink down');
        }
    });

    event(new PasswordChanged('42', 'other'));

    expect(app(RealmResolver::class)->current()->identifier())->not->toBe('other');
    Exceptions::assertReported(RuntimeException::class);
});
