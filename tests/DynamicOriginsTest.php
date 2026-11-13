<?php

declare(strict_types=1);

use FancyPasskeys\PasskeyException;
use FancyPasskeys\RelyingParty;
use FancyPasskeys\Support\Base64Url;
use FancyPasskeys\Tests\Support\Ceremony;

/*
 * `$origins` as a Closure, for desktop apps whose origin is only known at run
 * time. Mirrors the Node twin's resolver: called on EVERY verification, and
 * every list it returns is held to exactly the construction rules.
 *
 * A Closure rather than any `callable` on purpose: `['https://a', 'https://b']`
 * is a valid origin list AND, for the wrong strings, a valid callable array.
 * Wrap a method with first-class callable syntax (`$this->origins(...)`).
 */

it('does not call the resolver at construction', function () {
    $calls = 0;
    $rp = new RelyingParty('example.com', 'Example App', function () use (&$calls): array {
        $calls++;

        return ['https://example.com'];
    });

    expect($calls)->toBe(0);
    expect($rp->hasDynamicOrigins())->toBeTrue();
});

it('resolves on every call, not once', function () {
    $port = 5000;
    $rp = new RelyingParty('localhost', 'Desktop', function () use (&$port): array {
        return ["http://localhost:{$port}"];
    });

    expect($rp->origins())->toBe(['http://localhost:5000']);
    $port = 5001;
    expect($rp->origins())->toBe(['http://localhost:5001']);
});

it('passes a resolved accept row, as at construction', function (string $rpId, string $origin) {
    $rp = new RelyingParty($rpId, 'Example App', static fn (): array => [$origin]);

    expect($rp->origins())->toBe([$origin]);
})->with(relyingPartyOriginRows('accept'));

it('refuses a resolved reject row, as at construction', function (string $rpId, string $origin) {
    // An IP-literal RP ID throws at construction, before any resolver runs.
    // Either way the configuration never reaches a validator.
    $rp = new RelyingParty($rpId, 'Example App', static fn (): array => [$origin]);
    $rp->origins();
})->with(relyingPartyOriginRows('reject'))->throws(InvalidArgumentException::class);

it('refuses a bad value on EVERY call, not just the first', function () {
    $origin = 'https://example.com';
    $rp = new RelyingParty('example.com', 'Example App', function () use (&$origin): array {
        return [$origin];
    });

    $origin = 'http://example.com';
    expect(fn () => $rp->origins())->toThrow(InvalidArgumentException::class, 'https');
    $origin = 'https://example.com';
    expect($rp->origins())->toBe(['https://example.com']);
    $origin = 'https://evil.test';
    expect(fn () => $rp->origins())->toThrow(InvalidArgumentException::class);
});

it('refuses what the resolver returns when it is not an origin list', function (Closure $resolver) {
    (new RelyingParty('example.com', 'Example App', $resolver))->origins();
})->with([
    'an empty list' => [static fn (): array => []],
    'a string' => [static fn (): string => 'https://example.com'],
    'a non-string entry' => [static fn (): array => [42]],
    'an origin with no scheme' => [static fn (): array => ['example.com']],
])->throws(InvalidArgumentException::class);

it('propagates a resolver that throws, rather than allowing anything', function () {
    $rp = new RelyingParty('example.com', 'Example App', static function (): array {
        throw new RuntimeException('config service down');
    });

    $rp->origins();
})->throws(RuntimeException::class, 'config service down');

describe('setOrigins', function () {
    it('replaces a static list, validated immediately', function () {
        $rp = new RelyingParty('localhost', 'Desktop', ['http://localhost:5000']);
        $rp->setOrigins(['http://localhost:6000']);

        expect($rp->origins())->toBe(['http://localhost:6000']);
        expect($rp->hasDynamicOrigins())->toBeFalse();
    });

    it('leaves the previous list in place when the new one is refused', function () {
        $rp = new RelyingParty('localhost', 'Desktop', ['http://localhost:5000']);

        expect(fn () => $rp->setOrigins(['http://127.0.0.1:6000']))->toThrow(InvalidArgumentException::class);
        expect(fn () => $rp->setOrigins([]))->toThrow(InvalidArgumentException::class);
        expect($rp->origins())->toBe(['http://localhost:5000']);
    });

    it('can switch to a resolver and back', function () {
        $rp = new RelyingParty('localhost', 'Desktop', ['http://localhost:5000']);
        $rp->setOrigins(static fn (): array => ['http://localhost:7000']);

        expect($rp->hasDynamicOrigins())->toBeTrue();
        expect($rp->origins())->toBe(['http://localhost:7000']);

        $rp->setOrigins(['http://localhost:5000']);
        expect($rp->hasDynamicOrigins())->toBeFalse();
    });
});

/*
 * The REAL ceremony step manager, and the contrast pattern from
 * OriginValidationTest: the same response is stopped at the origin check while
 * the resolver excludes its origin, and gets past it (to the deliberately
 * nonsense signature) once the resolver includes it.
 */
function assertWithOrigins(RelyingParty $rp, string $responseOrigin): PasskeyException
{
    $credential = makeStoredCredential('Y3JlZC1hbGljZQ', ALICE_HANDLE);
    $server = makePasskeyServer([$credential], rp: $rp);
    $start = $server->startAuthentication(ALICE_HANDLE);

    $response = Ceremony::authenticationResponse(
        $start['publicKey']['challenge'],
        Base64Url::decode($credential->id),
        ALICE_HANDLE,
        origin: $responseOrigin,
    );

    try {
        $server->finishAuthentication($start['state'], $response);
    } catch (PasskeyException $e) {
        return $e;
    }

    throw new RuntimeException('A response with a nonsense signature was accepted.');
}

describe('PasskeyServer with a resolver', function () {
    it('uses the list resolved for THIS verification', function () {
        $allowed = ['https://example.com'];
        $rp = new RelyingParty('example.com', 'Example App', function () use (&$allowed): array {
            return $allowed;
        });

        expect(assertWithOrigins($rp, 'https://app.example.com')->getPrevious()?->getMessage())->toContain('origin');

        $allowed = ['https://app.example.com'];
        expect(assertWithOrigins($rp, 'https://app.example.com')->getPrevious()?->getMessage())->not->toContain('origin');
    });

    it('never reaches the validator when the resolved list is invalid', function () {
        $rp = new RelyingParty('example.com', 'Example App', static fn (): array => ['http://example.com']);

        // InvalidArgumentException, a configuration error: not a PasskeyException
        // a client would be shown as an ordinary failed login.
        expect(fn () => assertWithOrigins($rp, 'https://example.com'))->toThrow(InvalidArgumentException::class);
    });

    it('picks up setOrigins on a live server', function () {
        $rp = new RelyingParty('example.com', 'Example App', ['https://example.com']);

        expect(assertWithOrigins($rp, 'https://app.example.com')->getPrevious()?->getMessage())->toContain('origin');

        $rp->setOrigins(['https://app.example.com']);
        expect(assertWithOrigins($rp, 'https://app.example.com')->getPrevious()?->getMessage())->not->toContain('origin');
    });
});
