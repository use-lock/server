<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\Ui\Views;

use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

interface FactorSetupView
{
    public function respond(FactorSetupPrompt $prompt, Request $request): Responsable|Response;
}
