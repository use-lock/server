<?php

declare(strict_types=1);

namespace Lock\Server\Support\Maintenance\Commands;

use Illuminate\Console\Command;

class PruneCommand extends Command
{
    protected $signature = 'oidc:prune
        {--chunk=1000 : The number of records to delete per query}
        {--pretend : Report what would be deleted instead of deleting it}';

    protected $description = 'Delete the OIDC records that are spent: expired contexts and reset links, announced sessions, revoked and expired tokens';

    public function handle(): int
    {
        $models = [];

        foreach ($this->laravel->tagged('oidc.prunable') as $model) {
            $models[] = $model::class;
        }

        return $this->call('model:prune', [
            '--model' => $models,
            '--chunk' => $this->option('chunk'),
            '--pretend' => (bool) $this->option('pretend'),
        ]);
    }
}
