<?php

declare(strict_types=1);

use FancyPasskeys\PasskeyErrorCode;
use FancyPasskeys\PasskeyException;
use FancyPasskeys\PasskeyUser;
use FancyPasskeys\Support\Base64Url;
use FancyPasskeys\Tests\Support\Ceremony;

/*
 * The error contract shared with the Node twin, from
 * tests/fixtures/errors/codes.json (byte-identical in both repos).
 *
 * The fixture exists because the two backends had drifted on a named failure:
 * the `passkeys` lab benchmark (2026-11-13) saw a wrong-origin assertion answer
 * `origin_not_allowed` 400 from Node and `verification_failed` 401 from PHP.
 * One React surface sits in front of either backend, so the answer is part of
 * the wire contract, not an implementation detail.
 *
 * The ceremonies run the REAL web-auth ceremony steps.
 */

/** @return array<string, mixed> */
function errorFixture(): array
{
    return json_decode((string) file_get_contents(__DIR__ . '/fixtures/errors/codes.json'), true, 512, JSON_THROW_ON_ERROR);
}

/** @return array{code: string, status: int} */
function wireOf(Closure $fn): array
{
    try {
        $fn();
    } catch (PasskeyException $e) {
        return ['code' => $e->toArray()['error']['code'], 'status' => $e->httpStatus()];
    }

    throw new RuntimeException('Expected the ceremony to be refused, but it succeeded.');
}

it('lists every code this package emits, and no other', function () {
    $mine = array_map(static fn (PasskeyErrorCode $c): string => $c->value, PasskeyErrorCode::cases());
    $shared = array_keys(errorFixture()['codes']);

    sort($mine);
    sort($shared);

    expect($mine)->toBe($shared);
});

it('answers each code with the fixture\'s status and wire code', function (string $code, int $status, string $wire) {
    $e = new PasskeyException(PasskeyErrorCode::from($code));

    expect($e->httpStatus())->toBe($status);
    expect($e->toArray()['error']['code'])->toBe($wire);
})->with(function (): array {
    $rows = [];
    foreach (errorFixture()['codes'] as $code => $row) {
        $rows[$code] = [$code, $row['status'], $row['wire']];
    }

    return $rows;
});

it('answers each named ceremony failure as the fixture says', function (array $row) {
    $known = makeStoredCredential('Y3JlZC1vbmU', ALICE_HANDLE);
    $server = makePasskeyServer([$known]);

    if ($row['ceremony'] === 'registration') {
        $start = $server->startRegistration(new PasskeyUser(ALICE_HANDLE, 'alice@example.com', 'Alice'));
        $answer = wireOf(fn () => $server->finishRegistration(
            $start['state'],
            Ceremony::registrationResponse($start['publicKey']['challenge'], 'new-credential', origin: $row['clientDataOrigin']),
        ));
    } else {
        $start = $server->startAuthentication();
        $rawId = $row['credential'] === 'unknown' ? 'never-seen' : Base64Url::decode($known->id);
        $answer = wireOf(fn () => $server->finishAuthentication(
            $start['state'],
            Ceremony::authenticationResponse($start['publicKey']['challenge'], $rawId, ALICE_HANDLE, origin: $row['clientDataOrigin']),
        ));
    }

    expect($answer)->toBe(['code' => $row['code'], 'status' => $row['status']]);
})->with(function (): array {
    $rows = [];
    foreach (errorFixture()['ceremonies'] as $row) {
        $rows[$row['name']] = [$row];
    }

    return $rows;
});
