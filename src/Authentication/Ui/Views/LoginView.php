<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\Ui\Views;

use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

interface LoginView
{
    public function respond(LoginPrompt $prompt, Request $request): Responsable|Response;
}
