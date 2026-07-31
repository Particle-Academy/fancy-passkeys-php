<?php

declare(strict_types=1);

use FancyPasskeys\RelyingParty;

/*
 * Every one of these throws from the CONSTRUCTOR, on purpose.
 *
 * Deferred to login time, a misconfigured relying party surfaces as every
 * ceremony in production failing with an opaque browser error and no server-side
 * signal at all. Failing at boot turns that outage into a stack trace.
 */

it('rejects a relying party ID that is not a suffix of an origin', function () {
    new RelyingParty('other-site.com', 'Example App', ['https://example.com']);
})->throws(InvalidArgumentException::class, 'not valid for origin');

it('rejects a relying party ID that only shares a suffix textually', function () {
    // "notexample.com" ends with "example.com" as a string but is a different
    // registrable domain. This is the bug in every str_ends_with origin check.
    new RelyingParty('example.com', 'Example App', ['https://notexample.com']);
})->throws(InvalidArgumentException::class);

it('rejects an http origin that is not loopback', function () {
    new RelyingParty('example.com', 'Example App', ['http://example.com']);
})->throws(InvalidArgumentException::class, 'must use https');

it('rejects an empty origin list', function () {
    new RelyingParty('example.com', 'Example App', []);
})->throws(InvalidArgumentException::class);

it('rejects an empty relying party ID or name', function () {
    expect(fn () => new RelyingParty('', 'Example App', ['https://example.com']))
        ->toThrow(InvalidArgumentException::class);

    expect(fn () => new RelyingParty('example.com', '  ', ['https://example.com']))
        ->toThrow(InvalidArgumentException::class);
});

it('accepts http on localhost, where there is no network to intercept', function () {
    $rp = new RelyingParty('localhost', 'Example App', ['http://localhost:5173']);

    expect($rp->origins())->toBe(['http://localhost:5173']);
    expect($rp->host())->toBe('localhost');
});

it('accepts an apex relying party ID for a subdomain origin', function () {
    // The RP ID may be a registrable suffix of the origin host: a credential
    // minted for "example.com" works on app.example.com too.
    $rp = new RelyingParty('example.com', 'Example App', ['https://app.example.com']);

    expect($rp->host())->toBe('example.com');
});

it('defaults subdomain matching to off', function () {
    expect(testRelyingParty()->allowSubdomains)->toBeFalse();
});
