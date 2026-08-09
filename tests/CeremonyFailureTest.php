<?php

declare(strict_types=1);

use FancyPasskeys\PasskeyErrorCode;
use FancyPasskeys\PasskeyException;
use FancyPasskeys\PasskeyPolicy;
use FancyPasskeys\PasskeyUser;
use FancyPasskeys\Support\Base64Url;
use FancyPasskeys\Support\InMemoryCredentialStore;
use FancyPasskeys\Tests\Support\Ceremony;
use FancyPasskeys\Tests\Support\LeakyChallengeStore;
use FancyPasskeys\Tests\Support\TestClock;

/*
 * The failure paths, which are the only paths an attacker uses.
 *
 * None of these needs a real authenticator, and that is not a convenience — it
 * is the design being observable. Every check here fires BEFORE any signature
 * is verified, so a response that merely parses is enough to reach it. If one
 * of these tests ever starts needing a valid signature, the ordering has been
 * inverted and the anti-replay property is gone.
 */

const ALICE = ALICE_HANDLE;
const BOB = BOB_HANDLE;

it('rejects a replayed challenge', function () {
    $credential = makeStoredCredential('Y3JlZC1hbGljZQ', ALICE);
    $server = makePasskeyServer([$credential]);

    $start = $server->startAuthentication(ALICE);
    $response = Ceremony::authenticationResponse(
        $start['publicKey']['challenge'],
        Base64Url::decode($credential->id),
        ALICE,
    );

    // The first attempt fails on the signature, as it must — the response is
    // bogus. What matters is WHERE it failed: past the challenge, which is
    // therefore already gone.
    expect(errorCodeOf(fn () => $server->finishAuthentication($start['state'], $response)))
        ->not->toBe(PasskeyErrorCode::ChallengeNotFound);

    // Replay the exact same state + response. Had `pull()` waited for a
    // successful verification before deleting, this would fail identically to
    // the first attempt forever — including for a captured response that IS
    // valid.
    expect(errorCodeOf(fn () => $server->finishAuthentication($start['state'], $response)))
        ->toBe(PasskeyErrorCode::ChallengeNotFound);
});

it('rejects a replayed registration challenge', function () {
    $server = makePasskeyServer();
    $start = $server->startRegistration(new PasskeyUser(ALICE, 'alice@example.com', 'Alice'));
    $response = Ceremony::registrationResponse($start['publicKey']['challenge'], random_bytes(32));

    try {
        $server->finishRegistration($start['state'], $response);
    } catch (PasskeyException) {
        // expected — the attestation is not real
    }

    expect(errorCodeOf(fn () => $server->finishRegistration($start['state'], $response)))
        ->toBe(PasskeyErrorCode::ChallengeNotFound);
});

it('rejects an expired challenge even when the store hands it over', function () {
    $clock = new TestClock();
    $credential = makeStoredCredential('Y3JlZC1hbGljZQ', ALICE);

    // A store that does not enforce the TTL — a table with no sweeper, a cache
    // whose granularity rounds up, a replica running behind. The server's own
    // expiry check is the authoritative one.
    $server = makePasskeyServer(
        [$credential],
        challenges: new LeakyChallengeStore(),
        clock: $clock,
    );

    $start = $server->startAuthentication(ALICE);

    $clock->advanceSeconds(PasskeyPolicy::default()->challengeTtlSeconds + 1);

    $response = Ceremony::authenticationResponse(
        $start['publicKey']['challenge'],
        Base64Url::decode($credential->id),
        ALICE,
    );

    expect(errorCodeOf(fn () => $server->finishAuthentication($start['state'], $response)))
        ->toBe(PasskeyErrorCode::ChallengeExpired);
});

it('will not redeem a registration challenge at the authentication endpoint', function () {
    $credential = makeStoredCredential('Y3JlZC1hbGljZQ', ALICE);
    $server = makePasskeyServer([$credential]);

    $start = $server->startRegistration(new PasskeyUser(ALICE, 'alice@example.com', 'Alice'));

    $response = Ceremony::authenticationResponse(
        $start['publicKey']['challenge'],
        Base64Url::decode($credential->id),
        ALICE,
    );

    expect(errorCodeOf(fn () => $server->finishAuthentication($start['state'], $response)))
        ->toBe(PasskeyErrorCode::ChallengeTypeMismatch);
});

it('will not redeem an authentication challenge at the registration endpoint', function () {
    $server = makePasskeyServer();

    $start = $server->startAuthentication(ALICE);

    $response = Ceremony::registrationResponse($start['publicKey']['challenge'], random_bytes(32));

    expect(errorCodeOf(fn () => $server->finishRegistration($start['state'], $response)))
        ->toBe(PasskeyErrorCode::ChallengeTypeMismatch);
});

it('rejects an assertion for a credential it does not hold', function () {
    $server = makePasskeyServer();

    // Discoverable flow: no username, so the credential ID is the only thing
    // identifying the account.
    $start = $server->startAuthentication();

    $response = Ceremony::authenticationResponse(
        $start['publicKey']['challenge'],
        random_bytes(32),
        ALICE,
    );

    expect(errorCodeOf(fn () => $server->finishAuthentication($start['state'], $response)))
        ->toBe(PasskeyErrorCode::UnknownCredential);
});

it('refuses to register a credential ID that already belongs to another user', function () {
    $rawId = random_bytes(32);
    $alicesCredential = makeStoredCredential(Base64Url::encode($rawId), ALICE);

    $server = makePasskeyServer([$alicesCredential]);

    // Bob enrolls, and the response carries Alice's credential ID.
    $start = $server->startRegistration(new PasskeyUser(BOB, 'bob@example.com', 'Bob'));
    $response = Ceremony::registrationResponse($start['publicKey']['challenge'], $rawId);

    // Re-pointing an existing credential ID at a new account is account
    // takeover, so this is checked across ALL users — not just Bob's.
    expect(errorCodeOf(fn () => $server->finishRegistration($start['state'], $response)))
        ->toBe(PasskeyErrorCode::CredentialAlreadyRegistered);
});

it('refuses to register a credential ID the same user already has', function () {
    $rawId = random_bytes(32);
    $server = makePasskeyServer([makeStoredCredential(Base64Url::encode($rawId), ALICE)]);

    $start = $server->startRegistration(new PasskeyUser(ALICE, 'alice@example.com', 'Alice'));
    $response = Ceremony::registrationResponse($start['publicKey']['challenge'], $rawId);

    expect(errorCodeOf(fn () => $server->finishRegistration($start['state'], $response)))
        ->toBe(PasskeyErrorCode::CredentialAlreadyRegistered);
});

it('rejects a credential whose stored user handle is not the one the ceremony named', function () {
    $credential = makeStoredCredential('Y3JlZC1hbGljZQ', ALICE);
    $server = makePasskeyServer([$credential]);

    // The ceremony was started for Bob; the assertion presents Alice's
    // credential. A mismatch is an attack, not a curiosity.
    $start = $server->startAuthentication(BOB);

    $response = Ceremony::authenticationResponse(
        $start['publicKey']['challenge'],
        Base64Url::decode($credential->id),
        BOB,
    );

    expect(errorCodeOf(fn () => $server->finishAuthentication($start['state'], $response)))
        ->toBe(PasskeyErrorCode::UserHandleMismatch);
});

/**
 * The DISCOVERABLE half of cross-user credential reuse.
 *
 * The test above covers the username-first flow, where the wrapper compares the
 * stored handle against the one the ceremony named. In the discoverable flow
 * there IS no named account -- `startAuthentication()` takes no username -- so
 * that comparison is skipped entirely and the asserted handle is the ONLY thing
 * tying the credential to a user.
 *
 * The check is real but INVISIBLE from this repo: it lives in webauthn-lib's
 * CheckUserHandle, which we reach by passing a null expected handle. Nothing in
 * src/ shows it happening, so nothing here would notice if it stopped -- swap
 * the validator, or "tidy" that null into something non-null, and the branch
 * silently changes. That is exactly the class of auth bug that does not throw:
 * it accepts an assertion it should have refused, forever, and the suite stays
 * green. Hence these two.
 */
it('rejects a discoverable assertion whose reported handle is not the stored one', function () {
    $credential = makeStoredCredential('Y3JlZC1hbGljZQ', ALICE);
    $server = makePasskeyServer([$credential]);

    // No username: the credential is found on its ID alone, and it IS Alice's.
    $start = $server->startAuthentication();

    // ...but the authenticator claims it belongs to Bob. Accepting this is a
    // session as the wrong user, from a credential that verifies perfectly.
    $response = Ceremony::authenticationResponse(
        $start['publicKey']['challenge'],
        Base64Url::decode($credential->id),
        BOB,
    );

    expect(errorCodeOf(fn () => $server->finishAuthentication($start['state'], $response)))
        ->toBe(PasskeyErrorCode::UserHandleMismatch);
});

it('rejects a discoverable assertion that reports no handle at all', function () {
    $credential = makeStoredCredential('Y3JlZC1hbGljZQ', ALICE);
    $server = makePasskeyServer([$credential]);

    $start = $server->startAuthentication();

    // An absent handle must not read as "nothing to disagree with". In the
    // discoverable flow it is the whole identification step, so missing is a
    // refusal, not a pass.
    $response = Ceremony::authenticationResponse(
        $start['publicKey']['challenge'],
        Base64Url::decode($credential->id),
        null,
    );

    expect(errorCodeOf(fn () => $server->finishAuthentication($start['state'], $response)))
        ->toBe(PasskeyErrorCode::UserHandleMismatch);
});

it('rejects a response that is not the ceremony it was asked for', function () {
    $server = makePasskeyServer();
    $start = $server->startRegistration(new PasskeyUser(ALICE, 'alice@example.com', 'Alice'));

    // An assertion posted to the registration endpoint.
    $response = Ceremony::authenticationResponse($start['publicKey']['challenge'], random_bytes(32), ALICE);

    expect(errorCodeOf(fn () => $server->finishRegistration($start['state'], $response)))
        ->toBe(PasskeyErrorCode::InvalidResponse);
});

it('rejects an unparseable response', function () {
    $server = makePasskeyServer();
    $start = $server->startRegistration(new PasskeyUser(ALICE, 'alice@example.com', 'Alice'));

    expect(errorCodeOf(fn () => $server->finishRegistration($start['state'], ['not' => 'a credential'])))
        ->toBe(PasskeyErrorCode::InvalidResponse);
});

it('excludes the credentials a user already holds from a new registration', function () {
    $server = makePasskeyServer([
        makeStoredCredential('Y3JlZC1vbmU', ALICE, transports: ['internal']),
        makeStoredCredential('Y3JlZC10d28', ALICE, transports: ['usb']),
        makeStoredCredential('Y3JlZC10aHJlZQ', BOB),
    ]);

    $options = $server->startRegistration(new PasskeyUser(ALICE, 'alice@example.com', 'Alice'))['publicKey'];

    // The authenticator itself then refuses the duplicate, before the network
    // round-trip. Bob's credential is not Alice's business.
    expect(array_column($options['excludeCredentials'], 'id'))->toBe(['Y3JlZC1vbmU', 'Y3JlZC10d28']);
});

it('sends an empty allowCredentials for the discoverable flow', function () {
    $server = makePasskeyServer([makeStoredCredential('Y3JlZC1vbmU', ALICE)]);

    expect($server->startAuthentication()['publicKey']['allowCredentials'])->toBe([]);
});

it('issues a fresh 32-byte challenge and a distinct state handle every time', function () {
    $server = makePasskeyServer();

    $first = $server->startAuthentication();
    $second = $server->startAuthentication();

    expect(strlen(Base64Url::decode($first['publicKey']['challenge'])))->toBe(32);
    expect($first['publicKey']['challenge'])->not->toBe($second['publicKey']['challenge']);

    // Keying the store by the challenge itself would let anyone who observed
    // one options payload probe the store for it.
    expect($first['state'])->not->toBe($first['publicKey']['challenge']);
    expect($first['state'])->not->toBe($second['state']);
});

it('lists a user\'s passkeys as summaries without keys or counters', function () {
    $server = makePasskeyServer([
        makeStoredCredential('Y3JlZC1vbmU', ALICE),
        makeStoredCredential('Y3JlZC10d28', BOB),
    ]);

    $summaries = $server->listPasskeys(ALICE);

    expect($summaries)->toHaveCount(1);
    expect(array_keys($summaries[0]))->toBe([
        'id', 'name', 'createdAt', 'lastUsedAt', 'transports', 'backedUp', 'aaguid', 'clonedAt',
    ]);
});

it('does not tell the store to save anything when verification fails', function () {
    $store = new InMemoryCredentialStore();
    $server = makePasskeyServer(credentialStore: $store);

    $start = $server->startRegistration(new PasskeyUser(ALICE, 'alice@example.com', 'Alice'));

    try {
        $server->finishRegistration($start['state'], Ceremony::registrationResponse(
            $start['publicKey']['challenge'],
            random_bytes(32),
        ));
    } catch (PasskeyException) {
        // expected
    }

    expect($store->all())->toBe([]);
});
