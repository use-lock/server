<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('oidc_session_participants', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->uuid('session_id');
            $table->uuid('client_id');
            $table->timestamp('created_at');
            $table->string('logout_status')->nullable();
            $table->timestamp('logout_attempted_at')->nullable();
            $table->unique(['session_id', 'client_id']);
            $table->index('client_id');

            $table->foreign('session_id')->references('id')->on('oidc_sessions')->cascadeOnDelete();
            $table->foreign('client_id')->references('id')->on('oidc_clients')->cascadeOnDelete();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('oidc_session_participants');
    }
};
