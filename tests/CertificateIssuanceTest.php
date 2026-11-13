<?php

declare(strict_types=1);

use FancyPasskeys\CeremonyType;
use FancyPasskeys\IssuedLoginCertificate;
use FancyPasskeys\LoginCertificate;
use FancyPasskeys\LoginCertificates;
use FancyPasskeys\PasskeyErrorCode;
use FancyPasskeys\PasskeyException;
use FancyPasskeys\PasskeyServer;
use FancyPasskeys\PasskeyUser;
use FancyPasskeys\Support\Base64Url;
use FancyPasskeys\Support\InMemoryChallengeStore;
use FancyPasskeys\Support\InMemoryCredentialStore;
use FancyPasskeys\Tests\Support\SoftwareAuthenticator;
use FancyPasskeys\Tests\Support\TestClock;

/*
 * Login certificates are issued only after a ceremony SUCCEEDS, so these run
 * real ceremonies end to end through web-auth's validators, with a software
 * authenticator (tests/Support) playing the device. Mirrors the Node twin's
 * server-certificates.test.ts.
 */

/** 2026-11-13T09:30:00.000Z */
const CERT_CLOCK_MS = 1_794_562_200_000;

function certificateServer(?LoginCertificates $certificates = null): PasskeyServer
{
    $clock = new TestClock(CERT_CLOCK_MS);

    return new PasskeyServer(
        testRelyingParty(),
        \FancyPasskeys\PasskeyPolicy::default(),
        new InMemoryChallengeStore($clock->now(...)),
        new InMemoryCredentialStore(),
        $clock->now(...),
        testRandomBytes(),
        $certificates,
    );
}

/** @return array{credential: \FancyPasskeys\StoredCredential, summary: array<string, mixed>, certificate: ?IssuedLoginCertificate} */
function enroll(PasskeyServer $server, SoftwareAuthenticator $device, array $claims = []): array
{
    $start = $server->startRegistration(new PasskeyUser(ALICE_HANDLE, 'alice@example.com', 'Alice'));

    return $server->finishRegistration($start['state'], $device->register($start['publicKey']['challenge']), 'Laptop', $claims);
}

/** @return array{credential: \FancyPasskeys\StoredCredential, summary: array<string, mixed>, userHandle: string, certificate: ?IssuedLoginCertificate} */
function signIn(PasskeyServer $server, SoftwareAuthenticator $device, array $claims = []): array
{
    $start = $server->startAuthentication();

    return $server->finishAuthentication(
        $start['state'],
        $device->assert($start['publicKey']['challenge'], ALICE_HANDLE),
        $claims,
    );
}

it('completes a real registration and sign-in with the software authenticator', function () {
    // The baseline the rest of this file stands on: if this fails, nothing
    // below is testing what it claims to.
    $server = certificateServer();
    $device = new SoftwareAuthenticator();

    $enrolled = enroll($server, $device);
    expect($enrolled['credential']->id)->toBe($device->credentialId());

    $signedIn = signIn($server, $device);
    expect($signedIn['userHandle'])->toBe(ALICE_HANDLE);
    expect($signedIn['credential']->signCount)->toBe(1);
});

it('refuses, at construction, a policy algorithm web-auth cannot verify', function () {
    // Offered but unverifiable means: enrolls fine, can never sign in. That was
    // Ed25519's fate before the signature manager was built from the policy.
    new PasskeyServer(
        testRelyingParty(),
        new \FancyPasskeys\PasskeyPolicy(algorithms: [-7, -65535]),
        new InMemoryChallengeStore(),
        new InMemoryCredentialStore(),
    );
})->throws(InvalidArgumentException::class, 'COSE algorithm -65535');

describe('off by default', function () {
    it('issues nothing for sign-in or registration', function () {
        $server = certificateServer();
        $device = new SoftwareAuthenticator();

        expect(enroll($server, $device, ['ip' => '203.0.113.7'])['certificate'])->toBeNull();
        expect(signIn($server, $device, ['ip' => '203.0.113.7'])['certificate'])->toBeNull();
        expect($server->certificates())->toBeNull();
    });
});

describe('when enabled', function () {
    it('issues one on sign-in, carrying the ceremony facts and the claims', function () {
        $server = certificateServer(new LoginCertificates());
        $device = new SoftwareAuthenticator();
        enroll($server, $device);

        $issued = signIn($server, $device, ['ip' => '203.0.113.7', 'requestId' => 'req-1'])['certificate'];

        expect($issued)->toBeInstanceOf(IssuedLoginCertificate::class);
        expect($issued->certificate)->toMatchArray([
            'type' => 'fancy-passkeys.login-certificate',
            'version' => 1,
            'ceremony' => 'authentication',
            'issuedAt' => '2026-11-13T09:30:00.000Z',
            'rpId' => 'example.com',
            'credentialId' => $device->credentialId(),
            'userHandle' => ALICE_HANDLE,
            'claims' => ['ip' => '203.0.113.7', 'requestId' => 'req-1'],
        ]);
        expect($issued->certificate['nonce'])->toMatch('/^[A-Za-z0-9_-]{22}$/');
        expect($issued->token)->toMatch('/^fplc_v1_[0-9a-f]{64}$/');
        expect(LoginCertificate::verify($issued->certificate, $issued->token))->toBeTrue();
        expect(LoginCertificate::verify($issued->canonical, $issued->token))->toBeTrue();
    });

    it('issues one on registration, with the new credential', function () {
        $server = certificateServer(new LoginCertificates());
        $device = new SoftwareAuthenticator();

        $issued = enroll($server, $device, ['device' => 'Laptop'])['certificate'];

        expect($issued->certificate)->toMatchArray([
            'ceremony' => 'registration',
            'credentialId' => $device->credentialId(),
            'userHandle' => ALICE_HANDLE,
            'claims' => ['device' => 'Laptop'],
        ]);
    });

    it('can be limited to sign-in', function () {
        $server = certificateServer(new LoginCertificates(ceremonies: [CeremonyType::Authentication]));
        $device = new SoftwareAuthenticator();

        expect(enroll($server, $device)['certificate'])->toBeNull();
        expect(signIn($server, $device)['certificate'])->not->toBeNull();
    });

    it('gives every sign-in a different nonce and token', function () {
        $server = certificateServer(new LoginCertificates());
        $device = new SoftwareAuthenticator();
        enroll($server, $device);

        $first = signIn($server, $device, ['ip' => '203.0.113.7'])['certificate'];
        $second = signIn($server, $device, ['ip' => '203.0.113.7'])['certificate'];

        expect($first->certificate['nonce'])->not->toBe($second->certificate['nonce']);
        expect($first->token)->not->toBe($second->token);
    });

    it('strips known-sensitive claims and reports where', function () {
        $server = certificateServer(new LoginCertificates());
        $device = new SoftwareAuthenticator();
        enroll($server, $device);

        $issued = signIn($server, $device, [
            'ip' => '203.0.113.7',
            'password' => 'hunter2',
            'device' => ['name' => 'Phone', 'sessionId' => 'abc'],
        ])['certificate'];

        expect($issued->certificate['claims'])->toBe(['ip' => '203.0.113.7', 'device' => ['name' => 'Phone']]);
        expect($issued->stripped)->toBe(['claims.device.sessionId', 'claims.password']);
    });

    it('merges the host\'s default claims under the per-call claims', function () {
        $seen = null;
        $server = certificateServer(new LoginCertificates(claims: function (array $subject) use (&$seen): array {
            $seen = $subject;

            return ['app' => 'desktop', 'ip' => 'default'];
        }));
        $device = new SoftwareAuthenticator();
        enroll($server, $device);

        $issued = signIn($server, $device, ['ip' => '203.0.113.7'])['certificate'];

        expect($seen)->toBe([
            'ceremony' => 'authentication',
            'rpId' => 'example.com',
            'credentialId' => $device->credentialId(),
            'userHandle' => ALICE_HANDLE,
        ]);
        expect($issued->certificate['claims'])->toBe(['app' => 'desktop', 'ip' => '203.0.113.7']);
    });

    it('delivers the certificate and token to the host hook', function () {
        $delivered = [];
        $server = certificateServer(new LoginCertificates(deliver: function (IssuedLoginCertificate $issued) use (&$delivered): void {
            $delivered[] = $issued;
        }));
        $device = new SoftwareAuthenticator();

        $registration = enroll($server, $device)['certificate'];
        $signIn = signIn($server, $device)['certificate'];

        expect($delivered)->toHaveCount(2);
        expect($delivered[0])->toBe($registration);
        expect($delivered[1])->toBe($signIn);
    });

    it('fails the call when delivery fails', function () {
        $server = certificateServer(new LoginCertificates(
            ceremonies: [CeremonyType::Authentication],
            deliver: static function (): void {
                throw new RuntimeException('log sink down');
            },
        ));
        $device = new SoftwareAuthenticator();
        enroll($server, $device);

        signIn($server, $device);
    })->throws(RuntimeException::class, 'log sink down');

    it('issues nothing when the ceremony fails', function () {
        $delivered = 0;
        $server = certificateServer(new LoginCertificates(deliver: function () use (&$delivered): void {
            $delivered++;
        }));
        $device = new SoftwareAuthenticator();
        enroll($server, $device);
        expect($delivered)->toBe(1);

        // A different key under the same credential id: the signature fails.
        $impostor = new SoftwareAuthenticator($device->rawCredentialId, counter: 5);
        $start = $server->startAuthentication();

        try {
            $server->finishAuthentication($start['state'], $impostor->assert($start['publicKey']['challenge'], ALICE_HANDLE));
            $this->fail('An assertion from the wrong key was accepted.');
        } catch (PasskeyException $e) {
            expect($e->errorCode)->toBe(PasskeyErrorCode::VerificationFailed);
        }

        expect($delivered)->toBe(1);
    });
});
