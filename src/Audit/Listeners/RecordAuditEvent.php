<?php

declare(strict_types=1);

namespace Lock\Server\Audit\Listeners;

use Illuminate\Contracts\Container\Container;
use Illuminate\Http\Request;
use Lock\Server\Audit\Contracts\AuditSink;
use Lock\Server\Shared\Audit\AuditEvent;
use Lock\Server\Shared\Audit\SessionContext;
use Lock\Server\Shared\Realms\CurrentRealm;
use Throwable;

/** A broken audit sink must not fail the authentication or token operation. */
final readonly class RecordAuditEvent
{
    public function __construct(private Container $app) {}

    public function handle(AuditEvent $event): void
    {
        if (! config('oidc.audit.enabled', true)) {
            return;
        }

        try {
            $request = $this->request();

            $record = $event->auditRecord()->withRequestContext(
                ip: $request?->ip(),
                userAgent: $this->userAgent($request),
                sid: $this->sessionSid(),
            );

            $record->realm === null
                ? $this->app->make(AuditSink::class)->record($record)
                : CurrentRealm::runAs($record->realm, fn () => $this->app->make(AuditSink::class)->record($record));
        } catch (Throwable $exception) {
            report($exception);
        }
    }

    private function request(): ?Request
    {
        return $this->app->bound('request') ? $this->app->make('request') : null;
    }

    private function userAgent(?Request $request): ?string
    {
        $userAgent = $request?->userAgent();

        return is_string($userAgent) && $userAgent !== ''
            ? mb_substr($userAgent, 0, 255)
            : null;
    }

    private function sessionSid(): ?string
    {
        if (! $this->app->bound('session.store') || ! $this->app->make('session.store')->isStarted()) {
            return null;
        }

        return $this->app->make(SessionContext::class)->sid();
    }
}
