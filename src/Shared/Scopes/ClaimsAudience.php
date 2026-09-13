<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Scopes;

enum ClaimsAudience: string
{
    case IdToken = 'id_token';
    case Userinfo = 'userinfo';
}
