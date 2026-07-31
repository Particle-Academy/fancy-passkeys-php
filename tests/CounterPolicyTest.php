<?php

declare(strict_types=1);

use FancyPasskeys\PasskeyPolicy;
use FancyPasskeys\Support\Base64Url;
use FancyPasskeys\Support\CounterCheck;
use FancyPasskeys\Support\InMemoryCredentialStore;
use FancyPasskeys\Tests\Support\Ceremony;

/*
 * The signature counter is a one-shot clone detector, and the two ways to
 * defeat it silently are (1) never persisting the new value, so every
 * comparison is against 0, and (2) being stricter than reality, so the majority
 * of real passkeys are rejected and someone turns the whole thing off.
 *
 * NOTE: the library runs its own counter check LAST in the request ceremony —
 * after the signature — so the end-to-end regression path cannot be reached
 * without a real authenticator. The rule itself is tested here directly; the
 * policy wiring around it is asserted where it is observable.
 */

it('accepts two zero counters, because most real passkeys never leave zero', function () {
    // iCloud Keychain and Google Password Manager do not implement counters.
    // A strict "new > stored" rule rejects most passkeys in the world.
    expect(CounterCheck::regressed(0, 0))->toBeFalse();
});

it('accepts a counter that strictly advanced', function () {
    expect(CounterCheck::regressed(0, 1))->toBeFalse();
    expect(CounterCheck::regressed(41, 42))->toBeFalse();
});

it('treats an equal counter as a regression', function () {
    // Two devices with the same private key repeat a value before they lower one.
    expect(CounterCheck::regressed(42, 42))->toBeTrue();
});

it('treats a lower counter as a regression', function () {
    expect(CounterCheck::regressed(42, 41))->toBeTrue();
    expect(CounterCheck::regressed(1, 0))->toBeTrue();
});

it('defaults to rejecting a regression', function () {
    expect(PasskeyPolicy::default()->counterPolicy)->toBe('reject');
});

it('accepts only the three documented counter policies', function () {
    expect(PasskeyPolicy::COUNTER_POLICY)->toBe(['reject', 'log-only', 'ignore']);

    expect(fn () => new PasskeyPolicy(counterPolicy: 'whatever'))
        ->toThrow(InvalidArgumentException::class);
});

it('does not advance a stored counter when the assertion fails', function () {
    // Related to the same defect: a counter written before verification is a
    // counter an attacker can drive.
    $store = new InMemoryCredentialStore([makeStoredCredential('Y3JlZC1vbmU', ALICE_HANDLE, signCount: 5)]);
    $server = makePasskeyServer(credentialStore: $store);

    $start = $server->startAuthentication(ALICE_HANDLE);

    try {
        $server->finishAuthentication($start['state'], Ceremony::authenticationResponse(
            $start['publicKey']['challenge'],
            Base64Url::decode('Y3JlZC1vbmU'),
            ALICE_HANDLE,
            signCount: 99,
        ));
    } catch (FancyPasskeys\PasskeyException) {
        // expected — the signature is nonsense
    }

    expect($store->findById('Y3JlZC1vbmU')->signCount)->toBe(5);
    expect($store->findById('Y3JlZC1vbmU')->lastUsedAt)->toBeNull();
});
