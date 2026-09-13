<?php

declare(strict_types=1);

namespace Lock\Server\Authentication\Pipeline;

use Closure;
use Illuminate\Support\Facades\Log;
use Throwable;

class PostLoginPipeline
{
    /** @var list<Closure> */
    private array $hooks = [];

    public function register(Closure $hook): void
    {
        $this->hooks[] = $hook;
    }

    public function run(LoginEvent $event): LoginApi
    {
        $api = new LoginApi;

        foreach ($this->hooks as $hook) {
            try {
                $hook($event, $api);
            } catch (Throwable $exception) {
                Log::error('oidc: postLogin hook threw; denying login (fail-closed): '.$exception->getMessage(), [
                    'exception' => $exception,
                ]);
                $api->deny('post_login_error');

                return $api;
            }

            if ($api->isDenied()) {
                return $api;
            }
        }

        return $api;
    }
}
