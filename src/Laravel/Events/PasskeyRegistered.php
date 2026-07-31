<?php

declare(strict_types=1);

namespace FancyPasskeys\Laravel\Events;

use FancyPasskeys\StoredCredential;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;

final class PasskeyRegistered
{
    use Dispatchable;

    public function __construct(
        public readonly Authenticatable $user,
        public readonly StoredCredential $credential,
    ) {
    }
}
