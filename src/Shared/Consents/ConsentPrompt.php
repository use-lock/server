<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Consents;

use Illuminate\Contracts\Auth\Authenticatable;
use Lock\Server\Shared\Clients\Client;
use Lock\Server\Shared\Scopes\Scope;

final readonly class ConsentPrompt
{
    /**
     * The approve form field carrying the value chosen for the nth open
     * template, counted in the order the request names them.
     */
    public static function parameterField(int $position): string
    {
        return 'scope_parameter_'.$position;
    }

    /**
     * @param  array<int, Scope>  $scopes
     * @param  list<string>  $resources  the resource identifiers the scopes are asked for; the realm's own issuer
     *                                   when the client named none. A scope means what the resource declaring it
     *                                   says it means, so a screen that hides this hides half the decision.
     */
    public function __construct(
        public Client $client,
        public Authenticatable $user,
        public array $scopes,
        public string $authToken,
        public array $resources,
    ) {}
}
