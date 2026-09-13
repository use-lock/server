<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\Concerns;

use Illuminate\Auth\SessionGuard;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Lock\Server\Shared\Authentication\IdentityGuard;
use Lock\Server\Shared\Realms\RealmResolver;
use RuntimeException;

trait ResolvesIdentityGuard
{
    private function guardName(): string
    {
        return IdentityGuard::name();
    }

    private function homeUrl(): string
    {
        return app(RealmResolver::class)->current()->login()->home;
    }

    private function currentUser(Request $request): ?Authenticatable
    {
        return $request->user($this->guardName());
    }

    private function sessionGuard(): SessionGuard
    {
        $guard = Auth::guard($this->guardName());

        if (! $guard instanceof SessionGuard) {
            throw new RuntimeException('OIDC authentication requires a session guard.');
        }

        return $guard;
    }

    private function statusResponse(Request $request, string $statusKey, int $code): JsonResponse|RedirectResponse
    {
        return $request->wantsJson()
            ? new JsonResponse('', $code)
            : back()->with('status', $statusKey);
    }
}
