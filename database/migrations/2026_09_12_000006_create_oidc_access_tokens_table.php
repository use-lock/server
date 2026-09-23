<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Lock\Server\Support\ForeignKeys;

/**
 * `auth_code_id` labels the refresh chain a token belongs to, and deliberately
 * carries no foreign key: `oidc:purge` removes a spent code long before the
 * chain it started expires. A cascade would take live tokens with it, and a
 * null would make a replayed refresh token stop revoking its chain.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('oidc_access_tokens', function (Blueprint $table): void {
            $table->char('id', 80)->primary();
            $table->string('realm');
            $table->foreignUuid('user_id')->nullable()->index();
            $table->foreignUuid('client_id');
            $table->json('scopes')->nullable();
            $table->json('audience')->nullable();
            $table->uuid('auth_code_id')->nullable()->index();
            $table->uuid('context_id')->nullable();
            $table->timestamp('revoked_at')->nullable();
            $table->timestamps();
            $table->timestamp('expires_at')->nullable()->index();

            $table->index(['realm', 'client_id']);

            $table->foreign(['realm', 'client_id'])->references(['realm', 'id'])->on('oidc_clients')->cascadeOnDelete();
            ForeignKeys::realm($table);
            ForeignKeys::user($table);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('oidc_access_tokens');
    }
};
