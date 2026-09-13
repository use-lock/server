<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Lock\Server\Support\ForeignKeys;

/**
 * One row per (realm, user, client, resource): the union of every scope the
 * user has ever approved for that client at that resource. Withdrawal sets
 * `revoked_at` rather than deleting, so a later approval reuses the row.
 *
 * The resource is part of the identity of a consent because the same scope
 * name means a different thing at each resource server that declares it —
 * without it, an approval for one resource would cover every other.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('oidc_consents', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->string('realm');
            $table->uuid('user_id');
            $table->foreignUuid('client_id');
            $table->string('resource');
            $table->json('scopes');
            $table->timestamp('granted_at');
            $table->timestamp('revoked_at')->nullable();
            $table->timestamps();

            $table->unique(['realm', 'user_id', 'client_id', 'resource']);

            $table->index(['realm', 'client_id']);

            $table->foreign(['realm', 'client_id'])->references(['realm', 'id'])->on('oidc_clients')->cascadeOnDelete();
            ForeignKeys::realm($table);
            ForeignKeys::user($table);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('oidc_consents');
    }
};
