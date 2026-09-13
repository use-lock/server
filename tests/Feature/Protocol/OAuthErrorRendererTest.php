<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;
use Lock\Server\Shared\Protocol\OAuthServerException;

it('renders expected OAuth failures without reporting them', function (): void {
    $log = Log::spy();
    Route::get('/oauth-error-test', fn () => throw OAuthServerException::invalidGrant('The grant has expired.'));

    $this->get('/oauth-error-test')
        ->assertBadRequest()
        ->assertExactJson(['error' => 'invalid_grant', 'error_description' => 'The grant has expired.'])
        ->assertHeader('Cache-Control', 'no-store, private')
        ->assertHeader('Pragma', 'no-cache');

    $log->shouldNotHaveReceived('error');
});
