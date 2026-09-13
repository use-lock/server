<?php

declare(strict_types=1);

it('surfaces the OIDC section with the resolved session-token guard', function (): void {
    config([
        'oidc.issuer' => 'https://app.test',
        'oidc.auth.guard' => 'identity',
        'oidc.session.token.guard' => null,
    ]);

    $this->artisan('about --only=oidc')
        ->assertSuccessful()
        ->expectsOutputToContain('Session Token Guard')
        ->expectsOutputToContain('identity');
});
