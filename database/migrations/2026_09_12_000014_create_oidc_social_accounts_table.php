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
        Schema::create('oidc_social_accounts', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->string('realm');
            $table->uuid('user_id')->index();
            $table->string('provider');
            $table->string('provider_user_id');
            $table->string('email')->nullable();
            $table->string('name')->nullable();
            $table->string('nickname')->nullable();
            $table->string('avatar')->nullable();
            $table->text('access_token')->nullable();
            $table->text('refresh_token')->nullable();
            $table->timestamp('token_expires_at')->nullable();
            $table->json('raw')->nullable();
            $table->timestamps();

            $table->unique(['realm', 'provider', 'provider_user_id']);

            ForeignKeys::realm($table);
            ForeignKeys::user($table);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('oidc_social_accounts');
    }
};
