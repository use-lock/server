<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Log;
use Lock\Server\Audit\Sinks\LogAuditSink;
use Lock\Server\Shared\Audit\AuditEventType;
use Lock\Server\Shared\Audit\AuditRecord;
use Psr\Log\LoggerInterface;

/**
 * @param  array<string, mixed>  $context
 */
function auditRecord(AuditEventType $type, array $context = [], bool $failure = false): AuditRecord
{
    return new AuditRecord(
        type: $type,
        userId: '42',
        context: $context,
        failure: $failure,
        ip: '10.0.0.1',
        occurredAt: new DateTimeImmutable('2026-08-13T12:00:00+00:00'),
    );
}

it('logs failure records as warnings on the default channel', function (): void {
    $logger = Mockery::mock(LoggerInterface::class);
    $logger->expects('log')->withArgs(
        fn (string $level, string $message, array $context): bool => $level === 'warning'
            && $message === 'oidc: audit auth.login.failed'
            && $context['reason'] === 'invalid_credentials'
            && $context['user_id'] === '42'
            && $context['ip'] === '10.0.0.1'
            && $context['occurred_at'] === '2026-08-13T12:00:00+00:00'
            && ! array_key_exists('client_id', $context),
    );
    Log::shouldReceive('channel')->once()->with(null)->andReturn($logger);

    (new LogAuditSink)->record(auditRecord(AuditEventType::LoginFailed, ['reason' => 'invalid_credentials'], failure: true));
});

it('logs success records as info on the configured channel', function (): void {
    config()->set('oidc.audit.log_channel', 'audit');

    $logger = Mockery::mock(LoggerInterface::class);
    $logger->expects('log')->withArgs(
        fn (string $level, string $message): bool => $level === 'info'
            && $message === 'oidc: audit oauth.token.issued',
    );
    Log::shouldReceive('channel')->once()->with('audit')->andReturn($logger);

    (new LogAuditSink)->record(auditRecord(AuditEventType::TokenIssued));
});
