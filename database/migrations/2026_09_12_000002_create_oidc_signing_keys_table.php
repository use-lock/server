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
        Schema::create('oidc_signing_keys', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->string('realm')->index();
            $table->string('kid')->unique();
            $table->text('public_key');
            $table->text('private_key')->nullable();
            $table->timestamp('retired_at')->nullable()->index();
            $table->timestamps();

            ForeignKeys::realm($table);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('oidc_signing_keys');
    }
};
