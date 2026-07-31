<?php

declare(strict_types=1);

namespace FancyPasskeys\Laravel\Events;

use Illuminate\Foundation\Events\Dispatchable;

/**
 * The signature counter went backwards for this credential.
 *
 * Two devices holding the same private key eventually produce a counter that
 * regresses; that is the only thing the counter is for. Listen to this if you
 * want to notify the user, force a re-enrollment, or open a ticket — the
 * package's own response is limited to stamping `cloned_at` and (under the
 * default `reject` policy) failing the login.
 */
final class PasskeyCloneDetected
{
    use Dispatchable;

    public function __construct(
        public readonly string $credentialId,
        public readonly string $detectedAt,
    ) {
    }
}
