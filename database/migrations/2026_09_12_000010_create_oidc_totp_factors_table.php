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
        Schema::create('oidc_totp_factors', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->uuid('user_id')->index();
            $table->string('name');
            $table->text('secret');
            $table->timestamp('confirmed_at')->nullable();
            $table->unsignedBigInteger('last_used_timestep')->nullable();
            $table->timestamp('last_used_at')->nullable();
            $table->timestamps();

            ForeignKeys::user($table);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('oidc_totp_factors');
    }
};
