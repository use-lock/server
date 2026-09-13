<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Lock\Server\Support\ForeignKeys;

/**
 * `browser_session_id` is the browser session a login happened in, so ending
 * that browser session can end the OIDC session behind it without reading the
 * session payload.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('oidc_sessions', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->string('realm')->index();
            $table->uuid('user_id')->index();
            $table->string('browser_session_id')->nullable()->index();
            $table->timestamps();
            $table->timestamp('expires_at')->index();
            $table->timestamp('revoked_at')->nullable();
            $table->timestamp('logout_finished_at')->nullable();

            ForeignKeys::realm($table);
            ForeignKeys::user($table);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('oidc_sessions');
    }
};
