<?php

declare(strict_types=1);

/**
 * OpenID Connect Core 1.0 §2 (acr, amr); Discovery 1.0 §3 (acr_values_supported)
 */

use Lock\Server\Shared\Authentication\AcrResolver;

it('reports one level for a single method and another for several', function (): void {
    $resolver = app(AcrResolver::class);

    expect($resolver->fromAmr([]))->toBeNull()
        ->and($resolver->fromAmr(['pwd']))->toBe('1')
        ->and($resolver->fromAmr(['pwd', 'otp']))->toBe('2')
        ->and($resolver->fromAmr(['pwd', 'webauthn']))->toBe('2')
        ->and($resolver->supported())->toBe(['1', '2']);
});

it('uses the realm acr_values mapping', function (): void {
    config([
        'oidc.login.acr_single_factor' => 'urn:example:loa:1',
        'oidc.login.acr_multi_factor' => 'urn:example:loa:2',
    ]);

    $resolver = app(AcrResolver::class);

    expect($resolver->fromAmr(['pwd']))->toBe('urn:example:loa:1')
        ->and($resolver->fromAmr(['pwd', 'otp']))->toBe('urn:example:loa:2')
        ->and($resolver->supported())->toBe(['urn:example:loa:1', 'urn:example:loa:2']);
});

it('advertises a shared value once', function (): void {
    config(['oidc.login.acr_single_factor' => 'urn:mace:incommon:iap:silver', 'oidc.login.acr_multi_factor' => 'urn:mace:incommon:iap:silver']);

    expect(app(AcrResolver::class)->supported())->toBe(['urn:mace:incommon:iap:silver']);
});
