<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\Pipeline;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Lock\Server\Authentication\Contracts\DeviceRecognizer;

class NullDeviceRecognizer implements DeviceRecognizer
{
    public function isKnown(Authenticatable $user, Request $request): bool
    {
        return true;
    }
}
