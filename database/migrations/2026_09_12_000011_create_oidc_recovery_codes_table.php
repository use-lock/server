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
        Schema::create('oidc_recovery_codes', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->uuid('user_id')->index();
            $table->text('code');
            $table->timestamp('used_at')->nullable();
            $table->timestamps();

            ForeignKeys::user($table);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('oidc_recovery_codes');
    }
};
