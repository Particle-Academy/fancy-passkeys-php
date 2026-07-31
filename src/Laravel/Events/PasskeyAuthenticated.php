<?php

declare(strict_types=1);

namespace FancyPasskeys\Laravel\Events;

use FancyPasskeys\StoredCredential;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;

/**
 * Fired in addition to — never instead of — `Illuminate\Auth\Events\Login`.
 * Anything already listening on Fortify's login must not be able to tell a
 * passkey session from a password one.
 */
final class PasskeyAuthenticated
{
    use Dispatchable;

    public function __construct(
        public readonly Authenticatable $user,
        public readonly StoredCredential $credential,
    ) {
    }
}
