<?php

declare(strict_types=1);

use FancyPasskeys\PasskeyPolicy;
use FancyPasskeys\PasskeyServer;
use FancyPasskeys\PasskeyUser;
use FancyPasskeys\RelyingParty;
use FancyPasskeys\StoredCredential;
use FancyPasskeys\Support\Base64Url;
use FancyPasskeys\Support\InMemoryChallengeStore;
use FancyPasskeys\Support\InMemoryCredentialStore;

/*
 * The test that keeps the pair a pair.
 *
 * `@particle-academy/fancy-passkeys` (Node) and this package must emit the same
 * options payloads for the same inputs, because one React surface is pointed at
 * whichever backend the app happens to run. Without this assertion the two
 * drift by one field at a time and the UI silently starts depending on the
 * backend it was developed against.
 *
 * The expected files are generated from the real `@simplewebauthn/server` and
 * live in BOTH repos. Change a wire shape here and you change it there, in the
 * same session.
 */

function wireFixture(string $name): ?array
{
    $path = __DIR__ . '/fixtures/wire/' . $name;

    if (! is_file($path)) {
        return null;
    }

    /** @var array<string, mixed> $decoded */
    $decoded = json_decode((string) file_get_contents($path), true, 512, JSON_THROW_ON_ERROR);

    return $decoded;
}

/**
 * Recursively sort keys so two payloads that differ only in key order compare
 * identical, while a differing type or value still fails.
 */
function canonical(array $value): array
{
    ksort($value);

    foreach ($value as $key => $item) {
        if (is_array($item)) {
            $value[$key] = canonical($item);
        }
    }

    return $value;
}

function wireParityServer(array $inputs): PasskeyServer
{
    $rp = new RelyingParty(
        $inputs['relyingParty']['id'],
        $inputs['relyingParty']['name'],
        $inputs['relyingParty']['origins'],
    );

    $policy = new PasskeyPolicy(
        $inputs['policy']['userVerification'],
        $inputs['policy']['residentKey'],
        $inputs['policy']['attestation'],
        $inputs['policy']['timeoutMs'],
        300,
        $inputs['policy']['algorithms'],
    );

    $credentials = new InMemoryCredentialStore(array_map(
        static fn (array $c): StoredCredential => new StoredCredential(
            id: $c['id'],
            publicKey: 'bm90LWEta2V5',
            userHandle: $inputs['user']['handle'],
            signCount: 0,
            transports: $c['transports'],
            createdAt: '2026-01-01T00:00:00.000Z',
        ),
        $inputs['existingCredentials'],
    ));

    $challenge = Base64Url::decode($inputs['challenge']);

    return new PasskeyServer(
        $rp,
        $policy,
        new InMemoryChallengeStore(),
        $credentials,
        static fn (): int => 1_700_000_000_000,
        // The fixture challenge, verbatim, for every draw — including the one
        // that becomes the `state` handle, which is not part of what is being
        // compared here.
        static fn (int $length): string => $challenge,
    );
}

it('emits registration options byte-identical to the Node twin', function () {
    $inputs = wireFixture('inputs.json');
    $expected = wireFixture('registration-options.json');

    if ($expected === null) {
        $this->markTestSkipped(
            'tests/fixtures/wire/registration-options.json is missing. It is generated from the real '
            . '@simplewebauthn/server in the fancy-passkeys-js repo and must be copied here; until it '
            . 'lands, PHP↔Node wire parity is UNVERIFIED.'
        );
    }

    $actual = wireParityServer($inputs)->startRegistration(new PasskeyUser(
        $inputs['user']['handle'],
        $inputs['user']['name'],
        $inputs['user']['displayName'],
    ))['publicKey'];

    expect(canonical($actual))->toBe(canonical($expected));
});

it('emits authentication options byte-identical to the Node twin', function () {
    $inputs = wireFixture('inputs.json');
    $expected = wireFixture('authentication-options.json');

    if ($expected === null) {
        $this->markTestSkipped(
            'tests/fixtures/wire/authentication-options.json is missing. It is generated from the real '
            . '@simplewebauthn/server in the fancy-passkeys-js repo and must be copied here; until it '
            . 'lands, PHP↔Node wire parity is UNVERIFIED.'
        );
    }

    $actual = wireParityServer($inputs)->startAuthentication($inputs['user']['handle'])['publicKey'];

    expect(canonical($actual))->toBe(canonical($expected));
});

it('emits the W3C JSON shapes the browser accepts without transformation', function () {
    // A standing guard for the fields the fixture would catch, so a wire change
    // is not invisible while the generated fixtures are absent.
    $inputs = wireFixture('inputs.json');
    $server = wireParityServer($inputs);

    $registration = $server->startRegistration(new PasskeyUser(
        $inputs['user']['handle'],
        $inputs['user']['name'],
        $inputs['user']['displayName'],
    ))['publicKey'];

    expect($registration['challenge'])->toBe($inputs['challenge']);
    expect($registration['rp'])->toBe(['id' => 'example.com', 'name' => 'Example App']);
    expect($registration['user'])->toBe([
        'id' => $inputs['user']['handle'],
        'name' => $inputs['user']['name'],
        'displayName' => $inputs['user']['displayName'],
    ]);
    expect($registration['pubKeyCredParams'])->toBe([
        ['type' => 'public-key', 'alg' => -8],
        ['type' => 'public-key', 'alg' => -7],
        ['type' => 'public-key', 'alg' => -257],
    ]);
    expect($registration['authenticatorSelection'])->toBe([
        'userVerification' => 'preferred',
        'residentKey' => 'preferred',
        'requireResidentKey' => false,
    ]);
    expect($registration['attestation'])->toBe('none');
    expect($registration['timeout'])->toBe(60000);
    expect($registration['excludeCredentials'])->toBe([
        ['type' => 'public-key', 'id' => 'Y3JlZC1vbmU', 'transports' => ['internal']],
        ['type' => 'public-key', 'id' => 'Y3JlZC10d28', 'transports' => ['usb', 'nfc']],
    ]);
    expect($registration['extensions'])->toBe(['credProps' => true]);
    expect($registration['hints'])->toBe([]);

    $authentication = $server->startAuthentication($inputs['user']['handle'])['publicKey'];

    expect($authentication['challenge'])->toBe($inputs['challenge']);
    expect($authentication['rpId'])->toBe('example.com');
    expect($authentication['userVerification'])->toBe('preferred');
    expect($authentication['timeout'])->toBe(60000);
    expect($authentication['allowCredentials'])->toBe([
        ['type' => 'public-key', 'id' => 'Y3JlZC1vbmU', 'transports' => ['internal']],
        ['type' => 'public-key', 'id' => 'Y3JlZC10d28', 'transports' => ['usb', 'nfc']],
    ]);
    expect($authentication)->not->toHaveKey('hints');
});

it('encodes an empty credential list as a JSON array, never an object', function () {
    $inputs = wireFixture('inputs.json');

    $options = wireParityServer($inputs)->startAuthentication()['publicKey'];

    // `{}` here breaks navigator.credentials.get(), and an associative PHP
    // array is exactly what encodes to `{}`.
    expect(json_encode($options['allowCredentials']))->toBe('[]');
});
