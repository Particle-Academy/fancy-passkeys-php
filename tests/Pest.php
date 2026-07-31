<?php

declare(strict_types=1);

use FancyPasskeys\Contracts\ChallengeStore;
use FancyPasskeys\Contracts\CredentialStore;
use FancyPasskeys\PasskeyPolicy;
use FancyPasskeys\PasskeyServer;
use FancyPasskeys\RelyingParty;
use FancyPasskeys\StoredCredential;
use FancyPasskeys\Support\InMemoryChallengeStore;
use FancyPasskeys\Support\InMemoryCredentialStore;
use FancyPasskeys\Tests\Support\TestClock;

/*
 * Core tests are pure unit tests — no framework binding at all, which is the
 * point of keeping Illuminate out of src/. Only tests/Laravel binds Testbench.
 */
uses(
    FancyPasskeys\Tests\Laravel\TestCase::class,
    Illuminate\Foundation\Testing\RefreshDatabase::class,
)->in('Laravel');

/** Two opaque base64url user handles, used across the ceremony tests. */
const ALICE_HANDLE = 'YWxpY2UtaGFuZGxlLTMyLWJ5dGVzLXh4eHh4eHg';
const BOB_HANDLE = 'Ym9iLWhhbmRsZS0zMi1ieXRlcy14eHh4eHh4eHg';

/**
 * Run the closure and return the {@see PasskeyErrorCode} it threw.
 */
function errorCodeOf(Closure $fn): FancyPasskeys\PasskeyErrorCode
{
    try {
        $fn();
    } catch (FancyPasskeys\PasskeyException $e) {
        return $e->errorCode;
    }

    throw new RuntimeException('Expected a PasskeyException, none was thrown.');
}

/**
 * A relying party matching tests/fixtures/wire/inputs.json.
 */
function testRelyingParty(): RelyingParty
{
    return new RelyingParty('example.com', 'Example App', ['https://example.com']);
}

/**
 * Deterministic "random" bytes.
 *
 * Distinct per call so the challenge and the state handle never collide — a
 * stub that returns one constant would hide a server that used the challenge
 * as its own store key, which is precisely the mistake §5.1 warns about.
 *
 * @return Closure(int): string
 */
function testRandomBytes(): Closure
{
    $call = 0;

    return static function (int $length) use (&$call): string {
        $call++;

        $bytes = '';
        for ($block = 0; strlen($bytes) < $length; $block++) {
            $bytes .= hash('sha256', "fancy-passkeys-test:{$call}:{$block}", true);
        }

        return substr($bytes, 0, $length);
    };
}

/**
 * @param  list<StoredCredential>  $credentials
 */
function makePasskeyServer(
    array $credentials = [],
    ?ChallengeStore $challenges = null,
    ?PasskeyPolicy $policy = null,
    ?TestClock $clock = null,
    ?RelyingParty $rp = null,
    ?CredentialStore $credentialStore = null,
): PasskeyServer {
    $clock ??= new TestClock();

    return new PasskeyServer(
        $rp ?? testRelyingParty(),
        $policy ?? PasskeyPolicy::default(),
        $challenges ?? new InMemoryChallengeStore($clock->now(...)),
        $credentialStore ?? new InMemoryCredentialStore($credentials),
        $clock->now(...),
        testRandomBytes(),
    );
}

/**
 * A credential that looks plausible enough for the checks that run before any
 * signature is verified. Its public key is not a key.
 */
function makeStoredCredential(
    string $id,
    string $userHandle,
    int $signCount = 0,
    array $transports = ['internal'],
): StoredCredential {
    return new StoredCredential(
        id: $id,
        publicKey: 'bm90LWEta2V5',
        userHandle: $userHandle,
        signCount: $signCount,
        transports: $transports,
        aaguid: '00000000-0000-0000-0000-000000000000',
        backedUp: false,
        backupEligible: false,
        uvInitialized: true,
        attestationFormat: 'none',
        name: 'Test key',
        createdAt: '2026-01-01T00:00:00.000Z',
    );
}
