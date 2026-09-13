<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Authentication;

use Illuminate\Contracts\Auth\Authenticatable;
use Lock\Server\Shared\Tokens\AccessTokenBearer;

interface RealmUser extends AccessTokenBearer, Authenticatable {}
