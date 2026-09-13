<?php

declare(strict_types=1);

use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Lock\Server\Brokering\Providers\GoogleProvider;
use Lock\Server\Brokering\SocialProviderRegistry;
use Lock\Server\Shared\Brokering\SocialCallback;
use Lock\Server\Shared\Brokering\SocialProvider;
use Lock\Server\Shared\Brokering\SocialUser;

it('omits providers without credentials and resolves configured ones', function (): void {
    config()->set('oidc.social.providers.google.client_id', 'g-client');
    config()->set('oidc.social.providers.google.client_secret', 'g-secret');

    $registry = app(SocialProviderRegistry::class);

    expect($registry->get('google'))->toBeInstanceOf(GoogleProvider::class)
        ->and($registry->get('github'))->toBeNull()
        ->and($registry->get('unknown'))->toBeNull()
        ->and(array_keys($registry->enabled()))->toBe(['google']);
});

it('resolves a custom driver registered through extend', function (): void {
    config()->set('oidc.social.providers.custom', ['driver' => 'my-driver', 'client_id' => 'x']);

    app(SocialProviderRegistry::class)->extend('my-driver', fn (string $key, array $config): SocialProvider => new readonly class($key) implements SocialProvider
    {
        public function __construct(private string $key) {}

        public function key(): string
        {
            return $this->key;
        }

        public function redirect(Request $request, string $intent = SocialProvider::INTENT_LOGIN): RedirectResponse
        {
            return redirect()->away('https://custom.test');
        }

        public function callback(Request $request): SocialCallback
        {
            return new SocialCallback(SocialProvider::INTENT_LOGIN, new SocialUser('c-1', null, false, null, null, null));
        }
    });

    expect(app(SocialProviderRegistry::class)->get('custom')?->key())->toBe('custom')
        ->and(app(SocialProviderRegistry::class)->enabled())->toHaveKey('custom');
});
