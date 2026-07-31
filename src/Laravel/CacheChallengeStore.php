<?php

declare(strict_types=1);

namespace FancyPasskeys\Laravel;

use FancyPasskeys\CeremonyType;
use FancyPasskeys\ChallengeRecord;
use FancyPasskeys\Contracts\ChallengeStore;
use Illuminate\Contracts\Cache\Repository;

/**
 * Challenges in the cache, keyed by the opaque `state` handle.
 *
 * Two independent things make a challenge single-use here: the cache TTL, and
 * `pull()` forgetting the key as it reads. Neither is sufficient alone — a TTL
 * still allows unlimited replays inside the window.
 *
 * Do not point this at the `array` driver in production: it is per-process, so
 * the worker that finishes the ceremony is usually not the one that started it.
 */
final readonly class CacheChallengeStore implements ChallengeStore
{
    public function __construct(
        private Repository $cache,
        private string $prefix = 'passkeys:challenge:',
    ) {
    }

    public function put(string $handle, ChallengeRecord $record): void
    {
        $ttl = (int) ceil(($record->expiresAt - $this->nowMs()) / 1000);

        if ($ttl <= 0) {
            return;
        }

        $this->cache->put($this->prefix . $handle, [
            'challenge' => $record->challenge,
            'type' => $record->type->value,
            'userHandle' => $record->userHandle,
            'expiresAt' => $record->expiresAt,
        ], $ttl);
    }

    public function pull(string $handle): ?ChallengeRecord
    {
        // Get-and-forget in one call. Read-then-verify-then-delete is how a
        // captured response becomes replayable.
        $payload = $this->cache->pull($this->prefix . $handle);

        if (! is_array($payload)) {
            return null;
        }

        $type = CeremonyType::tryFrom((string) ($payload['type'] ?? ''));

        if ($type === null) {
            return null;
        }

        $record = new ChallengeRecord(
            (string) ($payload['challenge'] ?? ''),
            $type,
            isset($payload['userHandle']) ? (string) $payload['userHandle'] : null,
            (int) ($payload['expiresAt'] ?? 0),
        );

        return $record->isExpired($this->nowMs()) ? null : $record;
    }

    private function nowMs(): int
    {
        return (int) (microtime(true) * 1000);
    }
}
