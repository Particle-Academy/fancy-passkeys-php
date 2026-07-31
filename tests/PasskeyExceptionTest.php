<?php

declare(strict_types=1);

use FancyPasskeys\PasskeyErrorCode;
use FancyPasskeys\PasskeyException;
use Webauthn\Exception\AuthenticatorResponseVerificationException;
use Webauthn\Exception\CounterException;
use Webauthn\Exception\InvalidDataException;
use Webauthn\Exception\InvalidUserHandleException;

it('maps every error code to a 4xx', function (PasskeyErrorCode $code) {
    // A failed ceremony is never a server error. The request was well-formed
    // enough to reach us and the answer is "no"; a 500 both reads as our bug
    // and signals that the failure shape differs by cause.
    expect($code->httpStatus())->toBeGreaterThanOrEqual(400)->toBeLessThan(500);
})->with(PasskeyErrorCode::cases());

it('gives every error code a non-empty client message', function (PasskeyErrorCode $code) {
    expect(trim($code->clientMessage()))->not->toBe('');
})->with(PasskeyErrorCode::cases());

it('returns 409 for a credential that is already registered', function () {
    expect(PasskeyErrorCode::CredentialAlreadyRegistered->httpStatus())->toBe(409);
});

it('returns 401 for the codes that mean authentication failed', function () {
    expect(PasskeyErrorCode::UnknownCredential->httpStatus())->toBe(401);
    expect(PasskeyErrorCode::VerificationFailed->httpStatus())->toBe(401);
    expect(PasskeyErrorCode::CounterRegressed->httpStatus())->toBe(401);
});

it('makes an unknown credential indistinguishable from a bad signature', function () {
    $unknown = PasskeyException::unknownCredential();
    $failed = PasskeyException::verificationFailed();

    // A distinct "we have never seen that credential" message is a
    // credential-existence oracle: it answers "is this passkey registered
    // here?" for anyone who can post to the endpoint.
    expect($unknown->getMessage())->toBe($failed->getMessage());
    expect($unknown->toArray()['error']['message'])->toBe($failed->toArray()['error']['message']);
    expect($unknown->httpStatus())->toBe($failed->httpStatus());
});

/*
 * Matching messages are not enough on their own.
 *
 * `code` is the field a client actually branches on, so a distinct code is just
 * as good an oracle as a distinct message. Each of these three reveals
 * something about a credential the server holds, and all three must reach the
 * client as `verification_failed`.
 */
it('redacts a credential-revealing code on the wire', function (PasskeyErrorCode $code, string $wouldLeak) {
    $exception = new PasskeyException($code);
    $failed = PasskeyException::verificationFailed();

    // True internally — a log, a listener, or a metric still gets the real
    // answer, which is what lets clone detection do its job.
    expect($exception->errorCode)->toBe($code);

    // Redacted on the way out, in every observable field at once.
    expect($code->wireCode())->toBe(PasskeyErrorCode::VerificationFailed);
    expect($exception->toArray())->toBe($failed->toArray());
    expect($exception->httpStatus())->toBe($failed->httpStatus());

    // And the thing it would otherwise have told a stranger is not in the body.
    expect(json_encode($exception->toArray()))->not->toContain($wouldLeak);
})->with([
    'no such credential here' => [PasskeyErrorCode::UnknownCredential, 'unknown_credential'],
    'exists, but not this account' => [PasskeyErrorCode::UserHandleMismatch, 'user_handle_mismatch'],
    'exists and looks cloned' => [PasskeyErrorCode::CounterRegressed, 'counter_regressed'],
]);

it('redacts the message whenever it redacts the code', function () {
    // Redacting the code but leaving a message that still names the real
    // failure would redact nothing at all.
    $exception = PasskeyException::counterRegressed();

    expect($exception->getMessage())->toContain('copied');
    expect($exception->toArray()['error']['message'])->not->toContain('copied');
});

it('leaves every non-redacted code exactly as it is', function (PasskeyErrorCode $code) {
    $redacted = [
        PasskeyErrorCode::UnknownCredential,
        PasskeyErrorCode::UserHandleMismatch,
        PasskeyErrorCode::CounterRegressed,
    ];

    if (in_array($code, $redacted, true)) {
        expect($code->wireCode())->toBe(PasskeyErrorCode::VerificationFailed);

        return;
    }

    expect($code->wireCode())->toBe($code);
    expect((new PasskeyException($code))->toArray()['error']['code'])->toBe($code->value);
})->with(PasskeyErrorCode::cases());

it('serialises to the wire error shape', function () {
    $body = PasskeyException::challengeExpired()->toArray();

    expect($body)->toBe([
        'error' => [
            'code' => 'challenge_expired',
            'message' => PasskeyErrorCode::ChallengeExpired->clientMessage(),
        ],
    ]);
});

it('maps a counter exception to counter_regressed', function () {
    $mapped = PasskeyException::fromWebauthn(CounterException::create(1, 5, 'Invalid counter.'));

    expect($mapped->errorCode)->toBe(PasskeyErrorCode::CounterRegressed);
});

it('maps an invalid user handle to user_handle_mismatch', function () {
    $mapped = PasskeyException::fromWebauthn(InvalidUserHandleException::create());

    expect($mapped->errorCode)->toBe(PasskeyErrorCode::UserHandleMismatch);
});

it('collapses every other library failure to verification_failed', function (Throwable $e) {
    // Wrong origin, wrong RP ID hash, missing user presence, unparseable
    // attestation and a bad signature all land here. Distinguishing them for
    // the caller is exactly the oracle we are trying not to build.
    expect(PasskeyException::fromWebauthn($e)->errorCode)->toBe(PasskeyErrorCode::VerificationFailed);
})->with([
    'origin' => fn () => AuthenticatorResponseVerificationException::create('Invalid origin.'),
    'data' => fn () => InvalidDataException::create(null, 'Invalid data.'),
    'unexpected' => fn () => new RuntimeException('Something upstream exploded.'),
]);

it('never leaks the upstream message into the client-visible message', function () {
    $upstream = AuthenticatorResponseVerificationException::create(
        'Invalid origin. Expected https://example.com but got https://evil.example.'
    );

    $mapped = PasskeyException::fromWebauthn($upstream);

    expect($mapped->getMessage())->not->toContain('evil.example');
    expect($mapped->getMessage())->not->toContain('Expected');
    expect($mapped->toArray()['error']['message'])->not->toContain('evil.example');

    // ...but it is right there for the log.
    expect($mapped->getPrevious())->toBe($upstream);
});

it('keeps the original throwable as previous for every factory', function () {
    $upstream = new RuntimeException('upstream');

    expect(PasskeyException::challengeNotFound($upstream)->getPrevious())->toBe($upstream);
    expect(PasskeyException::counterRegressed($upstream)->getPrevious())->toBe($upstream);
    expect(PasskeyException::invalidResponse($upstream)->getPrevious())->toBe($upstream);
});

it('exposes exactly the shared closed set of codes', function () {
    // The Node twin exports the identical union. Adding a case here without
    // adding it there breaks the pair, so the list is pinned.
    $codes = array_map(static fn (PasskeyErrorCode $c): string => $c->value, PasskeyErrorCode::cases());

    sort($codes);

    expect($codes)->toBe([
        'challenge_expired',
        'challenge_not_found',
        'challenge_type_mismatch',
        'counter_regressed',
        'credential_already_registered',
        'invalid_response',
        'not_supported',
        'origin_not_allowed',
        'rp_id_mismatch',
        'unknown_credential',
        'user_handle_mismatch',
        'user_verification_required',
        'verification_failed',
    ]);
});
