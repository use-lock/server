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

    public function __invoke(Request $request): Response
    {
        return $this->respondToInertia($request, ($this->complete)($request, approved: true));
    }
}
