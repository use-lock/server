<?php

declare(strict_types=1);

it('renders the configured brand icon on the auth pages', function (): void {
    config()->set('oidc-ui.brand_icon', 'acme-logo');

    $this->get(route('identity.login'), ['X-Inertia' => 'true'])
        ->assertOk()
        ->assertSee('acme-logo', false);
});
