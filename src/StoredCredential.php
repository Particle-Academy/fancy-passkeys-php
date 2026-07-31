<?php

declare(strict_types=1);

namespace FancyPasskeys;

/**
 * A persisted passkey, in exactly the shape the Node twin persists it.
 *
 * The record is per-credential, not per-user: the whole point of passkeys is
 * that one account enrolls a laptop, a phone, and a hardware key.
 */
final readonly class StoredCredential
{
    /**
     * @param  string  $id  base64url credential ID. Globally unique — see plan §5.3.
     * @param  string  $publicKey  base64url COSE key. The only thing that verifies a signature.
     * @param  string  $userHandle  base64url.
     * @param  list<string>  $transports
     * @param  string|null  $aaguid  Authenticator model UUID.
     * @param  bool|null  $backedUp  BS flag — is this passkey currently synced?
     * @param  bool|null  $backupEligible  BE flag — *can* it be synced?
     * @param  string|null  $attestationFormat  Stored, never trusted. See plan §5.7.
     * @param  string  $createdAt  ISO-8601.
     * @param  string|null  $lastUsedAt  ISO-8601.
     * @param  string|null  $clonedAt  ISO-8601. Stamped when the counter regressed.
     */
    public function __construct(
        public string $id,
        public string $publicKey,
        public string $userHandle,
        public int $signCount,
        public array $transports = [],
        public ?string $aaguid = null,
        public ?bool $backedUp = null,
        public ?bool $backupEligible = null,
        public ?bool $uvInitialized = null,
        public ?string $attestationFormat = null,
        public ?string $name = null,
        public string $createdAt = '',
        public ?string $lastUsedAt = null,
        public ?string $clonedAt = null,
    ) {
    }

    public function with(
        ?int $signCount = null,
        ?string $lastUsedAt = null,
        ?string $clonedAt = null,
        ?string $name = null,
    ): self {
        return new self(
            $this->id,
            $this->publicKey,
            $this->userHandle,
            $signCount ?? $this->signCount,
            $this->transports,
            $this->aaguid,
            $this->backedUp,
            $this->backupEligible,
            $this->uvInitialized,
            $this->attestationFormat,
            $name ?? $this->name,
            $this->createdAt,
            $lastUsedAt ?? $this->lastUsedAt,
            $clonedAt ?? $this->clonedAt,
        );
    }

    /**
     * `PasskeySummaryJSON` — the only credential shape that crosses the wire.
     *
     * Note what is absent: the public key and the sign counter. A management UI
     * has no use for either, and shipping them is a gift to anyone who gets a
     * read of the page.
     *
     * @return array{
     *     id: string,
     *     name: string|null,
     *     createdAt: string,
     *     lastUsedAt: string|null,
     *     transports: list<string>,
     *     backedUp: bool|null,
     *     aaguid: string|null,
     *     clonedAt: string|null
     * }
     */
    public function toSummary(): array
    {
        return [
            'id' => $this->id,
            'name' => $this->name,
            'createdAt' => $this->createdAt,
            'lastUsedAt' => $this->lastUsedAt,
            'transports' => $this->transports,
            'backedUp' => $this->backedUp,
            'aaguid' => $this->aaguid,
            'clonedAt' => $this->clonedAt,
        ];
    }
}
