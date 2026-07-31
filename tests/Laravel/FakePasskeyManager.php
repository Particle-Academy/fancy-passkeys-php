<?php

declare(strict_types=1);

namespace FancyPasskeys\Tests\Laravel;

use FancyPasskeys\Laravel\PasskeyManager;
use FancyPasskeys\PasskeyServer;
use FancyPasskeys\StoredCredential;

/**
 * A manager whose assertion always verifies.
 *
 * Completing a real authentication ceremony needs a real private key on a real
 * authenticator, which no test can have — and which is exactly the property
 * that makes a passkey worth having. So the *session* behaviour (guard, Login
 * event, session regeneration) is tested against a canned verification result,
 * and the verification itself is tested against the real library everywhere
 * else in this suite.
 */
final readonly class FakePasskeyManager extends PasskeyManager
{
    public function __construct(
        PasskeyServer $server,
        private StoredCredential $credential,
    ) {
        parent::__construct($server);
    }

    public function finishAuthentication(string $state, array|string $response): array
    {
        return [
            'credential' => $this->credential,
            'summary' => $this->credential->toSummary(),
            'userHandle' => $this->credential->userHandle,
        ];
    }
}
