<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Authentication;

use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\URL;
use Lock\Server\Shared\Realms\RealmResolver;

final readonly class LoginDestination
{
    public function __construct(private RealmResolver $realms) {}

    public function url(): string
    {
        $destination = $this->realms->current()->login()->loginRoute;

        return Route::has($destination)
            ? route($destination)
            : URL::to($destination);
    }
}
