<?php

declare(strict_types=1);

namespace FancyPasskeys\Support;

use Closure;
use FancyPasskeys\ChallengeRecord;
use FancyPasskeys\Contracts\ChallengeStore;

/**
 * A challenge store that lives for one process.
 *
 * Fine for tests and single-process scripts; useless behind more than one PHP
 * worker, which is every real deployment. Laravel apps get
 * `FancyPasskeys\Laravel\CacheChallengeStore`.
 */
final class InMemoryChallengeStore implements ChallengeStore
{
    /** @var array<string, ChallengeRecord> */
    private array $records = [];

    /** @var Closure(): int */
    private Closure $now;

    /**
     * @param  (Closure(): int)|null  $now  Epoch milliseconds. Injectable so tests
     *                                     do not have to sleep.
     */
    public function __construct(?Closure $now = null)
    {
        $this->now = $now ?? static fn (): int => (int) (microtime(true) * 1000);
    }

    public function put(string $handle, ChallengeRecord $record): void
    {
        $this->records[$handle] = $record;
    }

    public function pull(string $handle): ?ChallengeRecord
    {
        $record = $this->records[$handle] ?? null;

        // Delete first, unconditionally. Every path out of this method must
        // leave the handle unusable — that is what makes a replay fail at "no
        // such challenge" rather than at "bad signature".
        unset($this->records[$handle]);

        if ($record === null) {
            return null;
        }

        return $record->isExpired(($this->now)()) ? null : $record;
    }

    public function count(): int
    {
        return count($this->records);
    }
}
