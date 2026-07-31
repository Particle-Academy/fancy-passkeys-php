<?php

declare(strict_types=1);

namespace FancyPasskeys\Contracts;

use FancyPasskeys\PasskeyException;
use FancyPasskeys\StoredCredential;

/**
 * Credential persistence.
 *
 * `web-auth/webauthn-lib` v5 removed `PublicKeyCredentialSourceRepository`
 * entirely — lookup is the caller's job now, which means it is this interface.
 */
interface CredentialStore
{
    /**
     * @param  string  $id  base64url credential ID.
     */
    public function findById(string $id): ?StoredCredential;

    /** @return list<StoredCredential> */
    public function findByUserHandle(string $userHandle): array;

    /**
     * Persist a newly registered credential.
     *
     * A duplicate credential ID **must** throw
     * {@see PasskeyException::credentialAlreadyRegistered()} — for any user,
     * not just this one. A credential ID already registered elsewhere is either
     * an attack or a bug, and silently re-pointing it at a new account is
     * account takeover. A durable store should back this with a unique index;
     * the application-level check races, the index does not.
     *
     * @throws PasskeyException
     */
    public function save(StoredCredential $credential): void;

    /**
     * Persist the advanced signature counter after a successful assertion.
     *
     * Called on **every** success, including when the counter is 0.
     */
    public function updateAfterAuthentication(string $id, int $signCount, string $lastUsedAt): void;

    /**
     * Stamp the credential as having produced a regressed counter.
     *
     * The counter is a one-shot clone detector: fail the login without
     * recording it and the next attempt from the real device succeeds, the
     * counter catches up, and the signal is gone forever.
     */
    public function flagCloned(string $id, string $clonedAt): void;

    public function delete(string $id): void;
}
