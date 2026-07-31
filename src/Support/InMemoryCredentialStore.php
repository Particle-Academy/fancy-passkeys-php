<?php

declare(strict_types=1);

namespace FancyPasskeys\Support;

use FancyPasskeys\Contracts\CredentialStore;
use FancyPasskeys\PasskeyException;
use FancyPasskeys\StoredCredential;

/**
 * A credential store that lives for one process. Tests and scripts only.
 */
final class InMemoryCredentialStore implements CredentialStore
{
    /** @var array<string, StoredCredential> */
    private array $credentials = [];

    /** @param iterable<StoredCredential> $seed */
    public function __construct(iterable $seed = [])
    {
        foreach ($seed as $credential) {
            $this->credentials[$credential->id] = $credential;
        }
    }

    public function findById(string $id): ?StoredCredential
    {
        return $this->credentials[$id] ?? null;
    }

    public function findByUserHandle(string $userHandle): array
    {
        return array_values(array_filter(
            $this->credentials,
            static fn (StoredCredential $c): bool => $c->userHandle === $userHandle,
        ));
    }

    public function save(StoredCredential $credential): void
    {
        // Across ALL users, not just this one.
        if (isset($this->credentials[$credential->id])) {
            throw PasskeyException::credentialAlreadyRegistered();
        }

        $this->credentials[$credential->id] = $credential;
    }

    public function updateAfterAuthentication(string $id, int $signCount, string $lastUsedAt): void
    {
        $credential = $this->credentials[$id] ?? null;

        if ($credential === null) {
            return;
        }

        $this->credentials[$id] = $credential->with(signCount: $signCount, lastUsedAt: $lastUsedAt);
    }

    public function flagCloned(string $id, string $clonedAt): void
    {
        $credential = $this->credentials[$id] ?? null;

        if ($credential === null) {
            return;
        }

        $this->credentials[$id] = $credential->with(clonedAt: $clonedAt);
    }

    public function delete(string $id): void
    {
        unset($this->credentials[$id]);
    }

    /** @return list<StoredCredential> */
    public function all(): array
    {
        return array_values($this->credentials);
    }
}
