<?php

declare(strict_types=1);

namespace FancyPasskeys\Tests\Support;

/**
 * A clock the test moves by hand. Epoch milliseconds, like `PasskeyServer`'s.
 */
final class TestClock
{
    public function __construct(private int $nowMs = 1_700_000_000_000)
    {
    }

    public function now(): int
    {
        return $this->nowMs;
    }

    public function advanceSeconds(int $seconds): void
    {
        $this->nowMs += $seconds * 1000;
    }
}
