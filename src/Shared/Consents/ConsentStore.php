<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Consents;

use Lock\Server\Shared\Clients\Client;

interface ConsentStore
{
    /**
     * Whether the user holds an unrevoked consent for the client that covers
     * every requested scope at every one of the resources.
     *
     * @param  list<string>  $scopes
     * @param  list<string>  $resources
     */
    public function covers(string $userId, string $clientKey, array $scopes, array $resources): bool;

    /**
     * Records an approval: at each resource the scopes are merged into the
     * user's existing consent for the client, and a withdrawn consent becomes
     * active again.
     *
     * @param  list<string>  $scopes
     * @param  list<string>  $resources
     */
    public function grant(string $userId, Client $client, array $scopes, array $resources): void;
}
