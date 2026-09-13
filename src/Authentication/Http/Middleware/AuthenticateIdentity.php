<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\Http\Middleware;

use Illuminate\Auth\Middleware\Authenticate;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Http\Request;
use Lock\Server\Shared\Authentication\LoginDestination;

final class AuthenticateIdentity extends Authenticate
{
    public function __construct(
        AuthFactory $auth,
        private readonly LoginDestination $loginDestination,
    ) {
        parent::__construct($auth);
    }

    protected function redirectTo(Request $request): string
    {
        return $this->loginDestination->url();
    }
}
