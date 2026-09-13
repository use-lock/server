<?php

declare(strict_types=1);

namespace Lock\Server\Shared\Realms\Settings;

final readonly class LoginSettings
{
    /**
     * @param  string  $usernameField  the credential field the password login reads
     * @param  string  $home  where a signed-in user lands
     * @param  string  $loginRoute  route name or path the authorize endpoint sends anonymous users to
     * @param  string  $logoutRedirect  where end-session lands without a post_logout_redirect_uri
     * @param  array{single_factor: string, multi_factor: string}  $acrValues  the `acr` (OIDC Core §2) an authentication earns with one method in `amr` and with several
     */
    public function __construct(
        public string $usernameField = 'email',
        public string $home = '/dashboard',
        public string $loginRoute = 'identity.login',
        public string $logoutRedirect = '/',
        public array $acrValues = ['single_factor' => '1', 'multi_factor' => '2'],
    ) {}

    public static function fromConfig(): self
    {
        return new self(
            usernameField: (string) config('oidc.login.username', 'email'),
            home: (string) config('oidc.login.home', '/dashboard'),
            loginRoute: (string) config('oidc.login.route', 'identity.login'),
            logoutRedirect: (string) config('oidc.login.logout_redirect', '/'),
            acrValues: [
                'single_factor' => (string) config('oidc.login.acr_single_factor', '1'),
                'multi_factor' => (string) config('oidc.login.acr_multi_factor', '2'),
            ],
        );
    }
}
