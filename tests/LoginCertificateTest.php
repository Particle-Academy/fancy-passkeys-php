<?php

declare(strict_types=1);

use FancyPasskeys\CeremonyType;
use FancyPasskeys\LoginCertificate;
use FancyPasskeys\Support\CanonicalJson;

/*
 * The login-certificate vectors shared with the Node twin.
 *
 * `@particle-academy/fancy-passkeys` drives the SAME file
 * (tests/fixtures/login-certificate/vectors.json): given input X, both runtimes
 * must produce certificate C, canonical bytes B and token T. A token minted by
 * one backend has to verify on the other.
 *
 * Decoded with objects (assoc = false), because `{}` and `[]` are different
 * canonical bytes and an associative decode cannot tell them apart.
 */

function loginCertificateFixture(): stdClass
{
    return json_decode(
        (string) file_get_contents(__DIR__ . '/fixtures/login-certificate/vectors.json'),
        false,
        512,
        JSON_THROW_ON_ERROR,
    );
}

/** @return array<string, array{stdClass}> */
function loginCertificateRows(string $kind): array
{
    $rows = [];

    foreach (loginCertificateFixture()->{$kind} as $row) {
        $rows[$row->name] = [$row];
    }

    return $rows;
}

/** The fixture's `input`, as named arguments for LoginCertificate::issue(). */
function loginCertificateArgs(stdClass $input): array
{
    $args = get_object_vars($input);
    $args['claims'] ??= new stdClass();

    return $args;
}

/*
 * Computed with `printf '%s' '<canonical>' | sha256sum`, outside both packages,
 * so the first vector does not merely agree with whatever generated it.
 */
const MINIMAL_CANONICAL = '{"ceremony":"authentication","claims":{},"credentialId":"Y3JlZC1vbmU","issuedAt":"2026-11-13T09:30:00.000Z","nonce":"AAECAwQFBgcICQoLDA0ODw","rpId":"example.com","type":"fancy-passkeys.login-certificate","userHandle":"YWRhLXVzZXItaGFuZGxl","version":1}';
const MINIMAL_TOKEN = 'fplc_v1_2a5e10b3fda4de20f24436d9da848dee27212e1205782fa5383dc5f541ee929e';

it('loads a non-empty fixture', function () {
    $fixture = loginCertificateFixture();

    expect(count($fixture->vectors))->toBeGreaterThanOrEqual(4);
    expect(count($fixture->refuse))->toBeGreaterThanOrEqual(5);
    expect(count($fixture->mismatch))->toBeGreaterThanOrEqual(3);
    expect($fixture->tokenPrefix)->toBe(LoginCertificate::TOKEN_PREFIX);
});

it('pins the minimal vector to a hash computed outside the package', function () {
    $minimal = loginCertificateRows('vectors')['minimal'][0];

    expect($minimal->canonical)->toBe(MINIMAL_CANONICAL);
    expect($minimal->token)->toBe(MINIMAL_TOKEN);

    $issued = LoginCertificate::issue(...loginCertificateArgs($minimal->input));

    expect($issued->canonical)->toBe(MINIMAL_CANONICAL);
    expect($issued->token)->toBe(MINIMAL_TOKEN);
});

it('issues the vector exactly', function (stdClass $vector) {
    $issued = LoginCertificate::issue(...loginCertificateArgs($vector->input));

    expect($issued->canonical)->toBe($vector->canonical);
    expect($issued->token)->toBe($vector->token);
    expect($issued->stripped)->toBe($vector->stripped);
    expect(CanonicalJson::encode($issued->certificate))->toBe($vector->canonical);
    // Structurally too, not only as bytes.
    expect(json_decode(json_encode($issued->certificate, JSON_THROW_ON_ERROR)))->toEqual($vector->certificate);
})->with(loginCertificateRows('vectors'));

it('verifies the vector from the object, from its stored JSON, and from an associative decode', function (stdClass $vector) {
    expect(LoginCertificate::verify($vector->certificate, $vector->token))->toBeTrue();
    expect(LoginCertificate::verify($vector->canonical, $vector->token))->toBeTrue();
    expect(LoginCertificate::token($vector->certificate))->toBe($vector->token);

    // The common way a PHP app reads a stored row. Top-level `claims` is
    // always an object by schema, so an empty one survives this decode.
    $assoc = json_decode($vector->canonical, true, 512, JSON_THROW_ON_ERROR);

    if ($vector->name !== 'registration-unicode-and-edges') {
        expect(LoginCertificate::verify($assoc, $vector->token))->toBeTrue();
    } else {
        // That vector carries a NESTED empty object, which an associative decode
        // turns into a list. The README says: verify from the stored JSON.
        expect(LoginCertificate::verify($assoc, $vector->token))->toBeFalse();
    }
})->with(loginCertificateRows('vectors'));

it('refuses claims', function (stdClass $row) {
    $minimal = loginCertificateRows('vectors')['minimal'][0];
    $args = loginCertificateArgs($minimal->input);
    $args['claims'] = $row->claims;

    LoginCertificate::issue(...$args);
})->with(loginCertificateRows('refuse'))->throws(InvalidArgumentException::class);

it('does not verify', function (stdClass $row) {
    expect(LoginCertificate::verify($row->certificate, $row->token))->toBeFalse();
})->with(loginCertificateRows('mismatch'));

describe('issue', function () {
    $base = static fn (): array => [
        'ceremony' => 'authentication',
        'issuedAt' => '2026-11-13T09:30:00.000Z',
        'nonce' => 'AAECAwQFBgcICQoLDA0ODw',
        'rpId' => 'example.com',
        'credentialId' => 'Y3JlZC1vbmU',
        'userHandle' => 'YWRhLXVzZXItaGFuZGxl',
    ];

    it('accepts the ceremony as the enum', function () use ($base) {
        $args = $base();
        $args['ceremony'] = CeremonyType::Authentication;

        expect(LoginCertificate::issue(...$args)->token)->toBe(MINIMAL_TOKEN);
    });

    it('accepts claims as an empty PHP array and still writes {}', function () use ($base) {
        expect(LoginCertificate::issue(...$base(), claims: [])->canonical)->toBe(MINIMAL_CANONICAL);
    });

    it('makes a token of the prefix plus 64 lowercase hex characters', function () use ($base) {
        expect(LoginCertificate::issue(...$base())->token)->toMatch('/^fplc_v1_[0-9a-f]{64}$/');
    });

    it('does not let a claim overwrite a package field', function () use ($base) {
        $issued = LoginCertificate::issue(...$base(), claims: ['userHandle' => 'forged', 'ceremony' => 'registration']);

        expect($issued->certificate['userHandle'])->toBe('YWRhLXVzZXItaGFuZGxl');
        expect($issued->certificate['ceremony'])->toBe('authentication');
        expect($issued->certificate['claims'])->toBe(['userHandle' => 'forged', 'ceremony' => 'registration']);
    });

    it('refuses what has no canonical form shared with Node', function (mixed $claims) use ($base) {
        LoginCertificate::issue(...$base(), claims: $claims);
    })->with([
        'a float' => [['n' => 1.0]],
        'invalid UTF-8' => [['s' => "\xC3\x28"]],
        'an object that is not stdClass' => [['d' => new DateTimeImmutable('@0')]],
        'a closure' => [['f' => static fn () => 1]],
        'an integer past 2^53-1' => [['n' => PHP_INT_MAX]],
        'a list as claims' => [[1, 2]],
        'an integer key' => [[5 => 'x']],
    ])->throws(InvalidArgumentException::class);

    it('refuses bad package fields', function (array $override) use ($base) {
        LoginCertificate::issue(...array_replace($base(), $override));
    })->with([
        'an unknown ceremony' => [['ceremony' => 'signup']],
        'an empty rpId' => [['rpId' => '']],
        'an empty credentialId' => [['credentialId' => '']],
        'an empty userHandle' => [['userHandle' => '']],
        'a non-base64url nonce' => [['nonce' => 'not base64url!']],
        'an empty issuedAt' => [['issuedAt' => '']],
    ])->throws(InvalidArgumentException::class);
});

describe('verify', function () {
    it('is false, never a throw, for garbage', function () {
        expect(LoginCertificate::verify(null, MINIMAL_TOKEN))->toBeFalse();
        expect(LoginCertificate::verify('{not json', MINIMAL_TOKEN))->toBeFalse();
        expect(LoginCertificate::verify(['version' => 1], 42))->toBeFalse();
        expect(LoginCertificate::verify(['a' => 1.5], MINIMAL_TOKEN))->toBeFalse();
    });
});

describe('isSensitiveKey', function () {
    it('strips', function (string $key) {
        expect(LoginCertificate::isSensitiveKey($key))->toBeTrue();
    })->with([
        'password', 'Password', 'db_password', 'passwd', 'client_secret', 'accessToken',
        'csrf-token', 'api_key', 'X-Api-Key', 'Authorization', 'cookie', 'Set-Cookie',
        'privateKey', 'session_id', 'recovery_codes', 'otp', 'TOTP', 'pin', 'pwd', 'cvv',
        'ssn', 'session', 'auth',
    ]);

    it('keeps', function (string $key) {
        expect(LoginCertificate::isSensitiveKey($key))->toBeFalse();
    })->with(['ip', 'userAgent', 'requestId', 'device', 'passkeyName', 'footprint', 'authMethod', 'spin', 'user']);
});

describe('CanonicalJson (change-council\'s canonical form)', function () {
    // change-council's own assertion, so a local "improvement" that drifts from
    // the kit's one canonical form fails here first.
    it('sorts keys, keeps list order and refuses floats', function () {
        expect(CanonicalJson::encode(['b' => 1, 'a' => ['y' => 'é/', 'x' => [3, 1]]]))->toBe('{"a":{"x":[3,1],"y":"é/"},"b":1}')
            ->and(fn () => CanonicalJson::encode(['n' => 1.5]))->toThrow(InvalidArgumentException::class);
    });
});
