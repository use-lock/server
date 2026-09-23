<?php

declare(strict_types=1);

namespace Lock\Server\Tokens\Pipeline;

use Closure;
use Illuminate\Support\Facades\Log;
use Throwable;

/**
 * Trigger lists keyed by grant kind: `client_credentials`, `token_exchange`,
 * or `authorization_code`.
 */
class AccessTokenPipeline
{
    /** @var array<string, list<Closure>> */
    private array $triggers = [];

    public function register(string $kind, Closure $trigger): void
    {
        $this->triggers[$kind][] = $trigger;
    }

    public function has(string $kind): bool
    {
        return ($this->triggers[$kind] ?? []) !== [];
    }

    /** @param  array<string, mixed>  $context  seeded before the first trigger runs */
    public function run(string $kind, object $event, array $context = []): AccessTokenApi
    {
        $api = new AccessTokenApi;

        foreach ($context as $key => $value) {
            $api->setContext($key, $value);
        }

        foreach ($this->triggers[$kind] ?? [] as $trigger) {
            try {
                $trigger($event, $api);
            } catch (Throwable $exception) {
                Log::error("oidc: {$kind} trigger threw; denying access token (fail-closed): ".$exception->getMessage(), [
                    'exception' => $exception,
                ]);
                $api->deny("{$kind}_trigger_error");

                return $api;
            }

            if ($api->isDenied()) {
                return $api;
            }
        }

        return $api;
    }
}
