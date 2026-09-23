<?php

declare(strict_types=1);

namespace Lock\Server\Clients\Listeners;

use Illuminate\Database\Eloquent\Model;
use Lock\Server\Clients\Models\Client;
use Lock\Server\Shared\Maintenance\UserDeleting;

final class DeleteUserData
{
    public function handle(UserDeleting $event): void
    {
        $user = $event->user();

        Client::query()
            ->where('owner_type', $user instanceof Model ? $user->getMorphClass() : $user::class)
            ->where('owner_id', (string) $user->getAuthIdentifier())
            ->each(fn (Client $client) => $client->delete());
    }
}
