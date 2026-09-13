<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Consents;

use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

interface ConsentView
{
    public function respond(ConsentPrompt $prompt, Request $request): Responsable|Response;
}
