<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Brokering;

use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

interface SocialProvider
{
    public const string INTENT_LOGIN = 'login';

    public const string INTENT_LINK = 'link';

    public function key(): string;

    public function redirect(Request $request, string $intent = self::INTENT_LOGIN): Response;

    /** @throws SocialAuthenticationException */
    public function callback(Request $request): SocialCallback;
}
