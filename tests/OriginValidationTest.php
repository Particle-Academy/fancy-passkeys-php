<?php

declare(strict_types=1);

use FancyPasskeys\PasskeyErrorCode;
use FancyPasskeys\PasskeyException;
use FancyPasskeys\RelyingParty;
use FancyPasskeys\Support\Base64Url;
use FancyPasskeys\Tests\Support\Ceremony;

/*
 * These run the REAL ceremony step manager.
 *
 * The origin check sits early in `requestCeremony()` — after the allowed
 * credential list, the user handle, the client-data type and the challenge, but
 * well before the signature — so a response that merely parses is enough to
 * reach it. That is what makes this testable without an authenticator, and it
 * is also why a wrong-origin response can never reach the signature check.
 */

it('rejects a response whose clientDataJSON origin is not on the allow-list', function () {
    $credential = makeStoredCredential('Y3JlZC1hbGljZQ', ALICE_HANDLE);
    $server = makePasskeyServer([$credential]);

    $start = $server->startAuthentication(ALICE_HANDLE);

    $response = Ceremony::authenticationResponse(
        $start['publicKey']['challenge'],
        Base64Url::decode($credential->id),
        ALICE_HANDLE,
        origin: 'https://evil.example',
    );

    try {
        $server->finishAuthentication($start['state'], $response);
        $this->fail('A disallowed origin was accepted.');
    } catch (PasskeyException $e) {
        expect($e->errorCode)->toBe(PasskeyErrorCode::VerificationFailed);

        // It really was the origin that stopped it, not something further on:
        // the library's own message says so. That message stays in `previous`,
        // for the log — the client is told nothing.
        expect($e->getPrevious()?->getMessage())->toContain('origin');
        expect($e->getMessage())->not->toContain('evil.example');
        expect($e->toArray()['error']['message'])->not->toContain('origin');
    }
});

it('lets the allowed origin through to the signature check', function () {
    // The contrast case. Same response, same everything, correct origin — and
    // now it gets all the way to the cryptography before failing, because the
    // signature is (deliberately) nonsense. Without this, the test above would
    // also pass for a server that rejected every response for any reason.
    $credential = makeStoredCredential('Y3JlZC1hbGljZQ', ALICE_HANDLE);
    $server = makePasskeyServer([$credential]);

    $start = $server->startAuthentication(ALICE_HANDLE);

    $response = Ceremony::authenticationResponse(
        $start['publicKey']['challenge'],
        Base64Url::decode($credential->id),
        ALICE_HANDLE,
        origin: 'https://example.com',
    );

    try {
        $server->finishAuthentication($start['state'], $response);
        $this->fail('A response signed with nonsense was accepted.');
    } catch (PasskeyException $e) {
        expect($e->errorCode)->toBe(PasskeyErrorCode::VerificationFailed);
        expect($e->getPrevious()?->getMessage())->not->toContain('origin');
    }
});

it('rejects a subdomain of an allowed origin by default', function () {
    $credential = makeStoredCredential('Y3JlZC1hbGljZQ', ALICE_HANDLE);
    $server = makePasskeyServer([$credential]);

    $start = $server->startAuthentication(ALICE_HANDLE);

    $response = Ceremony::authenticationResponse(
        $start['publicKey']['challenge'],
        Base64Url::decode($credential->id),
        ALICE_HANDLE,
        origin: 'https://app.example.com',
    );

    try {
        $server->finishAuthentication($start['state'], $response);
        $this->fail('A subdomain origin was accepted with allowSubdomains off.');
    } catch (PasskeyException $e) {
        expect($e->getPrevious()?->getMessage())->toContain('Subdomains are not allowed');
    }
});

it('hands the ceremony exactly the configured origins and no subdomain wildcard', function () {
    /*
     * A structural companion to the behavioural tests above: these two values
     * are what `PasskeyServer` passes straight into
     * CeremonyStepManagerFactory::setAllowedOrigins($origins, $allowSubdomains).
     * Nothing widens them, nothing derives an origin from the request, and the
     * wildcard stays off unless an app turns it on knowingly.
     */
    $rp = new RelyingParty('example.com', 'Example App', ['https://example.com', 'https://www.example.com']);

    expect($rp->origins())->toBe(['https://example.com', 'https://www.example.com']);
    expect($rp->allowSubdomains)->toBeFalse();

    $opted = new RelyingParty('example.com', 'Example App', ['https://example.com'], allowSubdomains: true);

    expect($opted->allowSubdomains)->toBeTrue();
});
