<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Http;

use GuzzleHttp\Handler\CurlHandler;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Support\Facades\Http;
use InvalidArgumentException;
use LogicException;
use Symfony\Component\HttpFoundation\IpUtils;

final readonly class PublicHttpEndpoint
{
    public function __construct(private DnsResolver $dns) {}

    public function validate(string $uri): string
    {
        $parts = parse_url($uri);

        if (! is_array($parts)
            || strtolower($parts['scheme'] ?? '') !== 'https'
            || ! isset($parts['host'])
            || isset($parts['user'])
            || isset($parts['pass'])
            || array_key_exists('fragment', $parts)
            || preg_match('/[\x00-\x20\x7F\\\\]|%(?![0-9A-Fa-f]{2})/', $uri) === 1
            || filter_var($uri, FILTER_VALIDATE_URL) === false) {
            throw new InvalidArgumentException('The backchannel_logout_uri must be an absolute https URL without credentials or a fragment.');
        }

        $host = trim(strtolower($parts['host']), '[]');

        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            $this->assertPublicAddress($host);
        } elseif (filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false
            || preg_match('/\.[a-z][a-z0-9-]*\.?\z/i', $host) !== 1) {
            throw new InvalidArgumentException('The backchannel_logout_uri must name a public host.');
        }

        return $host;
    }

    public function request(string $uri): PendingRequest
    {
        $host = $this->validate($uri);
        $literal = filter_var($host, FILTER_VALIDATE_IP) !== false;
        $addresses = $literal ? [$host] : $this->dns->addresses($host);

        if ($addresses === []) {
            throw new ConnectionException('The back-channel logout host could not be resolved.');
        }

        foreach ($addresses as $address) {
            $this->assertPublicAddress($address);
        }

        if (! extension_loaded('curl')) {
            throw new LogicException('Back-channel logout requires the PHP cURL extension to pin the validated destination.');
        }

        $address = $addresses[0];
        $address = str_contains($address, ':') ? '['.$address.']' : $address;
        $port = parse_url($uri, PHP_URL_PORT) ?? 443;

        // Pin the checked address and bypass proxies so DNS cannot change the destination after validation.
        return Http::withOptions([
            'proxy' => '',
            'verify' => true,
            'allow_redirects' => false,
            'curl' => [CURLOPT_RESOLVE => $literal ? [] : ["{$host}:{$port}:{$address}"]],
        ])->setHandler(new CurlHandler);
    }

    private function assertPublicAddress(string $address): void
    {
        if (filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_GLOBAL_RANGE) === false
            || IpUtils::checkIp($address, [...IpUtils::PRIVATE_SUBNETS, '224.0.0.0/4', 'ff00::/8'])) {
            throw new InvalidArgumentException('The backchannel_logout_uri must resolve only to public IP addresses.');
        }
    }
}
