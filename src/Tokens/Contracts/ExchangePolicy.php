<?php

declare(strict_types=1);

namespace Lock\Server\Tokens\Contracts;

use Lock\Server\Tokens\Exchange\ExchangeGrantResult;
use Lock\Server\Tokens\Exchange\ExchangeRequest;

interface ExchangePolicy
{
    public function authorize(ExchangeRequest $request): ExchangeGrantResult;
}
