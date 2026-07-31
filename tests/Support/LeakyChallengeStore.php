<?php

declare(strict_types=1);

namespace FancyPasskeys\Tests\Support;

use FancyPasskeys\ChallengeRecord;
use FancyPasskeys\Contracts\ChallengeStore;

/**
 * A deliberately naive store: it deletes on read, but does **not** enforce the
 * TTL.
 *
 * Stores are consumer-supplied and their clocks are not ours — a table without
 * a sweeper, a cache whose TTL granularity rounds up, a Redis replica running
 * behind. This double exists to prove that `PasskeyServer`'s own expiry check
 * is the authoritative one, and that an expired record cannot get past it even
 * when the store hands it over.
 */
final class LeakyChallengeStore implements ChallengeStore
{
    /** @var array<string, ChallengeRecord> */
    private array $records = [];

    public function put(string $handle, ChallengeRecord $record): void
    {
        $this->records[$handle] = $record;
    }

    public function pull(string $handle): ?ChallengeRecord
    {
        $record = $this->records[$handle] ?? null;
        unset($this->records[$handle]);

        return $record;
    }
}
