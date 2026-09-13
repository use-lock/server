<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Lock\Server\Authentication\PasswordConfirmation;

class ShowConfirmedPasswordStatusController
{
    public function __invoke(Request $request): JsonResponse
    {
        return new JsonResponse([
            'confirmed' => PasswordConfirmation::confirmedRecently($request->session()),
        ]);
    }
}
