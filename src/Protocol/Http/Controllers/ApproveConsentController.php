<?php

declare(strict_types=1);

namespace Lock\Server\Protocol\Http\Controllers;

use Illuminate\Http\Request;
use Lock\Server\Protocol\Authorize\CompleteAuthorization;
use Lock\Server\Shared\Http\RespondsToInertiaExternalRedirects;
use Symfony\Component\HttpFoundation\Response;

class ApproveConsentController
{
    use RespondsToInertiaExternalRedirects;

    public function __construct(protected CompleteAuthorization $complete) {}

    /**
     * Approve a pending browser authorization request.
     *
     * Submit the consent form's `auth_token` with the authenticated browser
     * session and CSRF protection. The token is bound to the pending request
     * and consumed once. Success redirects to the client's validated redirect
     * URI with an authorization code; Inertia uses the external-redirect protocol.
     * This is a session-bound consent action, not a client-authenticated token API.
     */
    public function __invoke(Request $request): Response
    {
        return $this->respondToInertia($request, ($this->complete)($request, approved: true));
    }
}
