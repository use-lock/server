<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Tokens;

use Lock\Server\Shared\Authentication\LoginSnapshot;
use Lock\Server\Shared\Clients\Client;
use Lock\Server\Shared\Protocol\AuthorizeRequest;
use Lock\Server\Shared\Sessions\SessionSnapshot;

interface AuthorizationCodes
{
    public function issue(AuthorizeRequest $request, Client $client, SessionSnapshot $session, LoginSnapshot $login): string;
}
