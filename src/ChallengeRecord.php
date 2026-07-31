<?php

declare(strict_types=1);

namespace FancyPasskeys;

/**
 * One issued, not-yet-redeemed challenge.
 *
 * Stored server-side under an opaque random `state` handle — never under the
 * challenge itself, which would let anyone who observed one options payload
 * probe the store for it.
 */
final readonly class ChallengeRecord
{
    /**
     * @param  string  $challenge  base64url. The authoritative copy; the one in the
     *                             options payload is a courtesy to the authenticator.
     * @param  string|null  $userHandle  base64url, or null for the discoverable
     *                                   (usernameless) authentication flow.
     * @param  int  $expiresAt  Epoch milliseconds.
     */
    public function __construct(
        public string $challenge,
        public CeremonyType $type,
        public ?string $userHandle,
        public int $expiresAt,
    ) {
    }

    public function isExpired(int $nowMs): bool
    {
        return $nowMs >= $this->expiresAt;
    }
}
