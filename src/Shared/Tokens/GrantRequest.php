<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Tokens;

final readonly class GrantRequest
{
    /**
     * @param  array<string, mixed>  $parameters
     * @param  array<string, mixed>  $formParameters
     */
    public function __construct(
        public array $parameters,
        public string $endpoint,
        public array $formParameters = [],
    ) {}

    public function input(string $key, mixed $default = null): mixed
    {
        return array_key_exists($key, $this->parameters) ? $this->parameters[$key] : $default;
    }

    public function has(string $key): bool
    {
        return array_key_exists($key, $this->parameters);
    }
}
