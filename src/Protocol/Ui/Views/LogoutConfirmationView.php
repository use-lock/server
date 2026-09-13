<?php

declare(strict_types=1);

namespace Lock\Server\Protocol\Ui\Views;

use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Without a verifiable `id_token_hint`, require confirmation before logout
 * (OpenID Connect RP-Initiated Logout 1.0 §6).
 */
interface LogoutConfirmationView
{
    public function respond(LogoutPrompt $prompt, Request $request): Responsable|Response;
}
