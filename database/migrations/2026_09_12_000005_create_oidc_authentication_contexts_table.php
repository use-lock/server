<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Lock\Server\Support\ForeignKeys;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('oidc_authentication_contexts', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->string('realm')->index();
            $table->uuid('user_id')->index();
            $table->uuid('session_id')->nullable()->index();
            $table->json('amr');
            $table->string('acr')->nullable();
            $table->unsignedBigInteger('auth_time')->nullable();
            $table->json('id_token_claims');
            $table->json('access_token_claims');
            $table->timestamp('created_at');
            $table->timestamp('expires_at')->nullable()->index();

            $table->foreign('session_id')->references('id')->on('oidc_sessions')->cascadeOnDelete();
            ForeignKeys::realm($table);
            ForeignKeys::user($table);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('oidc_authentication_contexts');
    }
};
