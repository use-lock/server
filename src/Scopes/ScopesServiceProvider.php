<?php

declare(strict_types=1);

namespace Lock\Server\Scopes;

use Illuminate\Support\ServiceProvider;
use Lock\Server\Scopes\Claims\StandardClaimsResolver;
use Lock\Server\Shared\Scopes\ClaimsResolver;
use Lock\Server\Shared\Scopes\ScopeParameterPolicy;
use Lock\Server\Shared\Scopes\ScopeRepository;

class ScopesServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(ScopeRepository::class, ConfiguredScopeRepository::class);
        $this->app->singleton(ClaimsResolver::class, StandardClaimsResolver::class);
        $this->app->singleton(ScopeParameterPolicy::class, AssignedScopeParameterPolicy::class);
    }
}
