<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\Ui\Views;

use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

interface PasswordResetView
{
    public function respond(PasswordResetPrompt $prompt, Request $request): Responsable|Response;
}
