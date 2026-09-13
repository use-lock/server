<?php

declare(strict_types=1);

namespace Lock\Server\Credentials\Ui\Concerns;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Lock\Server\Shared\Ui\Support\ScreenSubject;

trait ManagesTwoFactor
{
    protected function twoFactorUser(): Authenticatable&Model
    {
        return ScreenSubject::currentOrFail();
    }

    protected function providerKey(): string
    {
        return (string) $this->context('provider', 'totp');
    }
}
