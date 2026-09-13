<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Scopes;

use Illuminate\Contracts\Auth\Authenticatable;

final readonly class ClaimsRequest
{
    /**
     * @param  list<string>  $scopes  The scopes granted on the token, already finalized by the scope repository.
     * @param  ?string  $clientId  Null only where the caller cannot attribute the request to a client.
     */
    public function __construct(
        public Authenticatable $user,
        public ClaimsAudience $audience,
        public ?string $clientId,
        public array $scopes,
    ) {}

    public function hasScope(string $scope): bool
    {
        return in_array($scope, $this->scopes, true);
    }
}
