<?php

declare(strict_types=1);

namespace Lock\Server\Authentication;

enum LoginOutcome
{
    case Denied;
    case MfaChallenge;
    case RequiredAction;
    case LoggedIn;
}
