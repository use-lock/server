<?php

declare(strict_types=1);

namespace Lock\Server\Tokens\Listeners;

use Lock\Server\Shared\Maintenance\UserDeleting;
use Lock\Server\Tokens\Models\AccessToken;
use Lock\Server\Tokens\Models\AuthenticationContext;
use Lock\Server\Tokens\Models\AuthorizationCode;

final class DeleteUserData
{
    public function handle(UserDeleting $event): void
    {
        AccessToken::query()->where('user_id', (string) $event->user()->getAuthIdentifier())->delete();
        AuthorizationCode::query()->where('user_id', (string) $event->user()->getAuthIdentifier())->delete();
        AuthenticationContext::query()->where('user_id', (string) $event->user()->getAuthIdentifier())->delete();
    }
}
