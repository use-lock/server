<?php

declare(strict_types=1);

namespace Lock\Server\Support;

use Illuminate\Database\Schema\Blueprint;

/**
 * The two foreign keys whose target belongs to the application rather than to
 * the package: `user_id` points at whatever table holds users, `realm` at
 * whatever table holds realms, if any. Both are configured under
 * `oidc.migrations`, and a null table writes no constraint at all.
 *
 * Only the migrations call this, so it is read exactly once per table.
 */
final class ForeignKeys
{
    public static function user(Blueprint $table, string $column = 'user_id'): void
    {
        self::constrain($table, $column, 'users');
    }

    public static function realm(Blueprint $table, string $column = 'realm'): void
    {
        self::constrain($table, $column, 'realms');
    }

    private static function constrain(Blueprint $table, string $column, string $target): void
    {
        $referenced = config("oidc.migrations.{$target}.table");

        if (! is_string($referenced) || $referenced === '') {
            return;
        }

        $table->foreign($column)
            ->references((string) config("oidc.migrations.{$target}.column", 'id'))
            ->on($referenced)
            ->cascadeOnDelete();
    }
}
