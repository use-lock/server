<?php

declare(strict_types=1);

namespace Lock\Server\Database\Factories\Concerns;

use Lock\Server\Clients\Models\Client;

trait ForClient
{
    /**
     * Unlike for(), this also moves the row into the client's realm, where
     * everything issued to the client lives.
     */
    public function forClient(Client $client): static
    {
        return $this->state(['client_id' => $client->getKey(), 'realm' => $client->realm]);
    }
}
