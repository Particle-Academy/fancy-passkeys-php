<?php

declare(strict_types=1);

use FancyPasskeys\RelyingParty;

/*
 * The origin / RP ID table shared with the Node twin.
 *
 * `@particle-academy/fancy-passkeys` drives the SAME file
 * (tests/fixtures/relying-party/origins.json), so both backends accept and
 * refuse exactly the same configurations. The table follows what Chromium
 * actually does for WebAuthn: any `*.localhost` host may use http, and an IP
 * literal is refused as an RP ID ("This is an invalid domain").
 */

// relyingPartyOriginTable() / relyingPartyOriginRows() live in Pest.php: the
// dynamic-origins test drives the same table through a resolver.

it('loads a non-empty table on both sides', function () {
    // A table that failed to load would make both datasets below vacuous.
    expect(count(relyingPartyOriginTable()['accept']))->toBeGreaterThan(5);
    expect(count(relyingPartyOriginTable()['reject']))->toBeGreaterThan(5);
});

it('accepts', function (string $rpId, string $origin) {
    $rp = new RelyingParty($rpId, 'Example App', [$origin]);

    expect($rp->origins())->toBe([$origin]);
    expect($rp->host())->toBe($rpId);
})->with(relyingPartyOriginRows('accept'));

it('refuses', function (string $rpId, string $origin) {
    new RelyingParty($rpId, 'Example App', [$origin]);
})->with(relyingPartyOriginRows('reject'))->throws(InvalidArgumentException::class);

it('refuses an IP-literal RP ID by name, not by accident of the suffix rule', function () {
    new RelyingParty('127.0.0.1', 'Example App', ['http://127.0.0.1:1']);
})->throws(InvalidArgumentException::class, 'IP');
