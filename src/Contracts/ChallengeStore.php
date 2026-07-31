<?php

declare(strict_types=1);

namespace FancyPasskeys\Contracts;

use FancyPasskeys\ChallengeRecord;

/**
 * Where issued challenges live between the two round-trips of a ceremony.
 *
 * The contract is small and the interesting half is {@see self::pull()}.
 */
interface ChallengeStore
{
    /**
     * @param  string  $handle  The opaque random `state` returned to the client.
     */
    public function put(string $handle, ChallengeRecord $record): void;

    /**
     * Read the record **and delete it in the same operation**.
     *
     * This is the entire anti-replay mechanism. An implementation that reads
     * without deleting — or that deletes only after a successful verification —
     * lets a captured, perfectly valid response be replayed forever, and
     * nothing anywhere reports it.
     *
     * An expired record must be treated as absent: delete it and return null.
     * The server checks expiry again on its own clock, so a store that cannot
     * enforce a TTL is still safe, just less tidy.
     */
    public function pull(string $handle): ?ChallengeRecord;
}
