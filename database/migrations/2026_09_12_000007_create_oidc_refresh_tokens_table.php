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
        Schema::create('oidc_refresh_tokens', function (Blueprint $table): void {
            $table->char('id', 80)->primary();
            $table->string('realm')->index();
            $table->char('access_token_id', 80)->index();
            $table->timestamp('revoked_at')->nullable();
            $table->timestamps();
            $table->timestamp('expires_at')->nullable()->index();

            $table->foreign('access_token_id')->references('id')->on('oidc_access_tokens')->cascadeOnDelete();
            ForeignKeys::realm($table);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('oidc_refresh_tokens');
    }
};
