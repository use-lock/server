<?php

declare(strict_types=1);

namespace Lock\Server\Audit;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;
use Lock\Server\Audit\Contracts\AuditSink;
use Lock\Server\Audit\Listeners\RecordAuditEvent;
use Lock\Server\Audit\Sinks\LogAuditSink;
use Lock\Server\Shared\Audit\AuditEvent;

class AuditServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(AuditSink::class, fn (Application $app): AuditSink => $app->make(
            (string) config('oidc.audit.sink', LogAuditSink::class),
        ));
    }

    public function boot(): void
    {
        Event::listen(AuditEvent::class, RecordAuditEvent::class);
    }
}
