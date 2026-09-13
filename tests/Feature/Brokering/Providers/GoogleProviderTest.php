<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Lock\Server\Brokering\Providers\GoogleProvider;

it('is pinned to the Google issuer regardless of config', function (): void {
    Http::fake([
        'https://accounts.google.com/.well-known/openid-configuration' => Http::response([
            'issuer' => 'https://accounts.google.com',
            'authorization_endpoint' => 'https://accounts.google.com/o/oauth2/v2/auth',
            'token_endpoint' => 'https://oauth2.googleapis.com/token',
            'jwks_uri' => 'https://www.googleapis.com/oauth2/v3/certs',
        ]),
    ]);

    $provider = new GoogleProvider('google', ['client_id' => 'client-1', 'client_secret' => 'shhh', 'issuer' => 'https://evil.test']);

    $request = Request::create('/auth/social/google');
    $request->setLaravelSession(app('session.store'));

    expect($provider->redirect($request)->headers->get('Location'))
        ->toStartWith('https://accounts.google.com/o/oauth2/v2/auth?');
});
