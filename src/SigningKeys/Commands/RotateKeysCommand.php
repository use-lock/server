<?php

declare(strict_types=1);

namespace Lock\Server\SigningKeys\Commands;

use Illuminate\Console\Command;
use Lock\Server\Shared\Realms\RealmResolver;
use Lock\Server\SigningKeys\Events\KeysRotated;
use Lock\Server\SigningKeys\SigningKeyGenerator;
use Lock\Server\SigningKeys\SigningKeyStore;
use RuntimeException;

class RotateKeysCommand extends Command
{
    protected $signature = 'oidc:rotate-keys
        {--force : Skip the confirmation prompt}
        {--if-missing : Only generate when no signing key exists yet (skips the confirmation prompt)}';

    protected $description = 'Generate a new OIDC signing keypair, retiring the current one for verification';

    public function __construct(
        private readonly SigningKeyGenerator $keys,
        private readonly SigningKeyStore $store,
        private readonly RealmResolver $realms,
    ) {
        parent::__construct();
    }

    public function handle(): int
    {
        $hasKeys = $this->keys->hasKeys();

        if ($this->option('if-missing') && $hasKeys) {
            $this->info('A signing key already exists; nothing to generate.');

            return self::SUCCESS;
        }

        if (! $this->option('force')
            && ! $this->option('if-missing')
            && ! $this->confirm('Generate a new signing keypair and store it?')) {
            $this->info('Aborted.');

            return self::SUCCESS;
        }

        $generated = $this->keys->generate();

        try {
            $this->store->rotate($generated);
        } catch (RuntimeException $exception) {
            $this->error($exception->getMessage());

            return self::FAILURE;
        }

        event(new KeysRotated($generated->kid, $this->realms->current()->identifier()));

        $this->info('New signing key generated. kid: '.$generated->kid);

        if ($hasKeys) {
            $this->line('The previous key stays in JWKS for verification. Delete it once every token it signed has expired.');
        }

        return self::SUCCESS;
    }
}
