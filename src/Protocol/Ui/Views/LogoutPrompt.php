<?php

declare(strict_types=1);

namespace Lock\Server\Protocol\Ui\Views;

use Illuminate\Contracts\Auth\Authenticatable;
use Lock\Server\Shared\Clients\Client;

final readonly class LogoutPrompt
{
    /**
     * @param  Client|null  $client  the relying party that initiated the logout, when the request identified one
     * @param  string|null  $postLogoutRedirectUri  the registered URI the browser lands on after logout; null means the realm's logout redirect
     * @param  string  $confirmationToken  must be posted back as `logout_confirmation` to perform the logout
     */
    public function __construct(
        public Authenticatable $user,
        public ?Client $client,
        public ?string $postLogoutRedirectUri,
        public ?string $state,
        public string $confirmationToken,
    ) {}
}
