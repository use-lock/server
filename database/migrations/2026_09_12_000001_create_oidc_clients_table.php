<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Lock\Server\Support\ForeignKeys;

/**
 * `id` is the internal key foreign keys point at; `client_id` is the identifier
 * relying parties send on the wire. Keeping them apart lets a client be renamed
 * without rewriting its tokens. A `client_id` only has to be unique within
 * its realm.
 *
 * `realm` (here and on every other scoped table) is an opaque identifier
 * the application owns — there is no realm table and no foreign key, exactly
 * as with `user_id`. A string rather than a uuid so a host-derived slug can be
 * stored without a lookup.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('oidc_clients', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->string('realm');
            $table->string('client_id');
            $table->nullableUuidMorphs('owner');
            $table->string('name');
            $table->text('secret')->nullable();
            $table->string('token_endpoint_auth_method');
            $table->json('redirect_uris');
            $table->json('post_logout_redirect_uris')->nullable();
            $table->json('grant_types');
            $table->json('default_scopes');
            $table->json('optional_scopes');
            $table->json('allowed_exchange_audiences')->nullable();
            $table->text('backchannel_logout_uri')->nullable();
            $table->boolean('backchannel_logout_session_required')->default(false);
            $table->boolean('consent_required')->default(true);
            $table->string('provisioning_key', 64)->nullable();
            $table->timestamp('revoked_at')->nullable();
            $table->timestamps();

            $table->unique(['realm', 'client_id']);
            $table->unique(['realm', 'id']);
            $table->unique(['realm', 'provisioning_key']);

            ForeignKeys::realm($table);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('oidc_clients');
    }
};
