<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        $usersTable = (string) config('passkeys.users.table', 'users');

        // A package migration cannot assume the host's users table exists yet,
        // or that it is even called "users" — and SQLite cannot add a foreign
        // key after the fact, so the decision has to be made here.
        $hasUsers = Schema::hasTable($usersTable);

        Schema::create((string) config('passkeys.table', 'passkey_credentials'), function (Blueprint $table) use ($usersTable, $hasUsers): void {
            $table->id();
            $table->foreignId('user_id')->index();

            if ($hasUsers) {
                $table->foreign('user_id')->references('id')->on($usersTable)->cascadeOnDelete();
            }

            /*
             * The unique index is the point of this migration.
             *
             * A credential ID registered to another account is either an attack
             * or a bug, and silently re-pointing it at a new account is account
             * takeover. The application-level check in PasskeyServer races with
             * a concurrent request; this index does not.
             *
             * 255 base64url characters is ~191 raw bytes. Real authenticators
             * emit 16-64 byte credential IDs (the spec allows up to 1023), and
             * 255 chars is the largest width MySQL can carry a unique index on
             * with utf8mb4. Widen it — and drop to a prefix index — only if you
             * meet an authenticator that needs it.
             */
            $table->string('credential_id', 255)->unique();

            $table->text('public_key');

            // Indexed because the discoverable flow looks credentials up by it.
            $table->string('user_handle', 128)->index();

            $table->unsignedBigInteger('sign_count')->default(0);
            $table->json('transports')->nullable();
            $table->string('aaguid', 36)->nullable();

            // BS / BE flags: is this passkey currently synced, and can it be?
            $table->boolean('backed_up')->nullable();
            $table->boolean('backup_eligible')->nullable();
            $table->boolean('uv_initialized')->nullable();

            // Stored so a future release can re-evaluate trust. NOT trusted now.
            $table->string('attestation_format', 32)->nullable();

            $table->string('name')->nullable();
            $table->timestamp('last_used_at')->nullable();

            // Stamped when the signature counter regressed. The counter is a
            // one-shot clone detector; a login that merely fails loses it.
            $table->timestamp('cloned_at')->nullable();

            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists((string) config('passkeys.table', 'passkey_credentials'));
    }
};
