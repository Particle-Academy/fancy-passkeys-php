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

        if (! Schema::hasTable($usersTable) || Schema::hasColumn($usersTable, 'passkey_user_handle')) {
            return;
        }

        Schema::table($usersTable, function (Blueprint $table): void {
            /*
             * The WebAuthn user handle: 32 random bytes, base64url, minted
             * lazily by HasPasskeys::passkeyUserHandle().
             *
             * It is NOT the primary key and NOT the email. Every authenticator
             * the user ever enrolls stores a copy of this value, so making it
             * the PK leaks an enumerable internal ID to every device — and to
             * anyone who can read one.
             *
             * Nullable because existing users have no handle until they enroll
             * their first passkey; unique because a handle identifies exactly
             * one account.
             */
            $table->string('passkey_user_handle', 128)->nullable()->unique();
        });
    }

    public function down(): void
    {
        $usersTable = (string) config('passkeys.users.table', 'users');

        if (! Schema::hasTable($usersTable) || ! Schema::hasColumn($usersTable, 'passkey_user_handle')) {
            return;
        }

        Schema::table($usersTable, function (Blueprint $table): void {
            $table->dropUnique([$table->getTable() . '_passkey_user_handle_unique']);
            $table->dropColumn('passkey_user_handle');
        });
    }
};
