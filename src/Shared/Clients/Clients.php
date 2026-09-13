<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Clients;

interface Clients
{
    public function find(string $clientId): ?Client;

    public function findActive(string $clientId): ?Client;

    public function findByKey(string $key, ?string $realm = null): ?Client;

    public function delete(string $key, string $realm): void;

    public function firstParty(): Client;

    public function authenticate(string $clientId, ?string $secret, TokenEndpointAuthMethod $method): Client;

    /** @param list<string> $keys
     * @return list<string>
     */
    public function logoutClientKeys(array $keys, string $realm): array;
}
