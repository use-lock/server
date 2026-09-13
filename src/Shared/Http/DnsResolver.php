<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Http;

use Illuminate\Http\Client\ConnectionException;

class DnsResolver
{
    /** @return list<string> */
    public function addresses(string $host): array
    {
        $records = dns_get_record($host, DNS_A | DNS_AAAA);

        if ($records === false) {
            throw new ConnectionException('The back-channel logout host could not be resolved.');
        }

        $addresses = [];

        foreach ($records as $record) {
            $address = $record['ip'] ?? $record['ipv6'] ?? null;

            if (is_string($address)) {
                $addresses[] = $address;
            }
        }

        return array_values(array_unique($addresses));
    }
}
