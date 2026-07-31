<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * The host application's users table, stood in for by the test harness.
 *
 * It has to be created by a MIGRATION rather than by the TestCase, and with a
 * timestamp earlier than the package's own: the package migrations add a column
 * to this table and hang a foreign key off it, and SQLite can do neither after
 * the fact. Creating it outside the migration run also loses it — an in-memory
 * SQLite database is per-connection, so a table created on a connection that is
 * later purged simply is not there any more.
 */
return new class extends Migration
{
    public function up(): void
    {
        if (Schema::hasTable('users')) {
            return;
        }

        Schema::create('users', function (Blueprint $table): void {
            $table->id();
            $table->string('name');
            $table->string('email')->unique();
            $table->string('password');
            $table->rememberToken();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('users');
    }
};
