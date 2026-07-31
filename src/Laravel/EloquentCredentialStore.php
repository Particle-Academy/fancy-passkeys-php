<?php

declare(strict_types=1);

namespace FancyPasskeys\Laravel;

use FancyPasskeys\Contracts\CredentialStore;
use FancyPasskeys\Laravel\Events\PasskeyCloneDetected;
use FancyPasskeys\Laravel\Models\PasskeyCredential;
use FancyPasskeys\PasskeyException;
use FancyPasskeys\StoredCredential;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\QueryException;
use RuntimeException;

/**
 * Credential persistence on Eloquent.
 *
 * The credential→user link is resolved through the user handle, not through a
 * caller-supplied ID: the handle is the only identifier that appears in a
 * WebAuthn ceremony, and going through it means a credential can never be
 * attached to an account the ceremony did not name.
 */
final class EloquentCredentialStore implements CredentialStore
{
    public function findById(string $id): ?StoredCredential
    {
        return PasskeyCredential::query()
            ->where('credential_id', $id)
            ->first()
            ?->toStoredCredential();
    }

    public function findByUserHandle(string $userHandle): array
    {
        return PasskeyCredential::query()
            ->where('user_handle', $userHandle)
            ->orderBy('id')
            ->get()
            ->map(static fn (PasskeyCredential $c): StoredCredential => $c->toStoredCredential())
            ->values()
            ->all();
    }

    public function save(StoredCredential $credential): void
    {
        // Across ALL users. Registered elsewhere it is either an attack or a
        // bug, and re-pointing it at this account is account takeover.
        if (PasskeyCredential::query()->where('credential_id', $credential->id)->exists()) {
            throw PasskeyException::credentialAlreadyRegistered();
        }

        $userId = $this->userIdForHandle($credential->userHandle);

        try {
            PasskeyCredential::query()->create([
                'user_id' => $userId,
                'credential_id' => $credential->id,
                'public_key' => $credential->publicKey,
                'user_handle' => $credential->userHandle,
                'sign_count' => $credential->signCount,
                'transports' => $credential->transports,
                'aaguid' => $credential->aaguid,
                'backed_up' => $credential->backedUp,
                'backup_eligible' => $credential->backupEligible,
                'uv_initialized' => $credential->uvInitialized,
                'attestation_format' => $credential->attestationFormat,
                'name' => $credential->name,
            ]);
        } catch (QueryException $e) {
            // The check above races with a concurrent request; the unique index
            // does not. Losing that race is still "already registered".
            throw PasskeyException::credentialAlreadyRegistered($e);
        }
    }

    public function updateAfterAuthentication(string $id, int $signCount, string $lastUsedAt): void
    {
        PasskeyCredential::query()
            ->where('credential_id', $id)
            ->update([
                'sign_count' => $signCount,
                'last_used_at' => $lastUsedAt,
            ]);
    }

    public function flagCloned(string $id, string $clonedAt): void
    {
        $updated = PasskeyCredential::query()
            ->where('credential_id', $id)
            ->update(['cloned_at' => $clonedAt]);

        if ($updated > 0) {
            PasskeyCloneDetected::dispatch($id, $clonedAt);
        }
    }

    public function delete(string $id): void
    {
        PasskeyCredential::query()->where('credential_id', $id)->delete();
    }

    private function userIdForHandle(string $handle): int|string
    {
        /** @var class-string<Model> $model */
        $model = config('passkeys.users.model') ?? config('auth.providers.users.model', 'App\\Models\\User');

        $user = $model::query()->where('passkey_user_handle', $handle)->first();

        if ($user === null) {
            throw new RuntimeException(
                'No user holds the passkey user handle this ceremony was issued for. Did the model forget '
                . 'the HasPasskeys trait, or was the handle minted on a different connection?'
            );
        }

        /** @var int|string $key */
        $key = $user->getKey();

        return $key;
    }
}
