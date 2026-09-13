<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\Pipeline;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Lock\Server\Authentication\Contracts\DeviceRecognizer;
use Lock\Server\Shared\Clients\Client;

final readonly class LoginEvent
{
    /**
     * @param  list<string>  $scopes
     * @param  list<string>  $requestedAcrValues
     * @param  list<string>  $amr
     */
    public function __construct(
        public Authenticatable $user,
        public ?Client $client,
        public array $scopes,
        public array $requestedAcrValues,
        public ?string $ip,
        public ?string $userAgent,
        public array $amr,
        public ?int $authTime,
        private DeviceRecognizer $recognizer,
        private Request $request,
    ) {}

    public function requestsAcr(string $value): bool
    {
        return in_array($value, $this->requestedAcrValues, true);
    }

    public function isNewDevice(): bool
    {
        return ! $this->recognizer->isKnown($this->user, $this->request);
    }
}
