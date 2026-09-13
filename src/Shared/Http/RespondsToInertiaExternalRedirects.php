<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Http;

use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Inertia XHR visits cannot follow external or custom-scheme redirects.
 * Use 409 + X-Inertia-Location for browser navigation:
 * https://inertiajs.com/redirects#external-redirects
 */
trait RespondsToInertiaExternalRedirects
{
    protected function respondToInertia(Request $request, Response $response): Response
    {
        if (! $request->hasHeader('X-Inertia') || ! $response->isRedirect() || ! $response->headers->has('Location')) {
            return $response;
        }

        return response('', 409, ['X-Inertia-Location' => $response->headers->get('Location')]);
    }
}
