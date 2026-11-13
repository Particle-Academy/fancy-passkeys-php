<?php

declare(strict_types=1);

use FancyPasskeys\CeremonyType;
use FancyPasskeys\IssuedLoginCertificate;
use FancyPasskeys\Laravel\Events\PasskeyCertificateIssued;
use FancyPasskeys\LoginCertificate;
use FancyPasskeys\LoginCertificates;
use FancyPasskeys\PasskeyServer;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;

/*
 * The Laravel wiring for login certificates: off unless config turns them on;
 * claims from the current request; delivery as an event the app listens to.
 * The issuing itself is tested end to end in tests/CertificateIssuanceTest.php.
 */

const BRIDGE_SUBJECT = [
    'ceremony' => 'authentication',
    'rpId' => 'localhost',
    'credentialId' => 'Y3JlZC1vbmU',
    'userHandle' => 'YWxpY2UtaGFuZGxlLTMyLWJ5dGVzLXh4eHh4eHg',
];

function rebuildPasskeyServer(): PasskeyServer
{
    app()->forgetInstance(LoginCertificates::class);
    app()->forgetInstance(PasskeyServer::class);

    return app(PasskeyServer::class);
}

it('is off by default', function () {
    expect(config('passkeys.certificates.enabled'))->toBeFalse();
    expect(rebuildPasskeyServer()->certificates())->toBeNull();
});

it('is on when config says so, for both ceremonies by default', function () {
    config()->set('passkeys.certificates.enabled', true);

    $certificates = rebuildPasskeyServer()->certificates();

    expect($certificates)->toBeInstanceOf(LoginCertificates::class);
    expect($certificates->appliesTo(CeremonyType::Authentication))->toBeTrue();
    expect($certificates->appliesTo(CeremonyType::Registration))->toBeTrue();
});

it('honours the configured ceremonies', function () {
    config()->set('passkeys.certificates.enabled', true);
    config()->set('passkeys.certificates.ceremonies', ['authentication']);

    $certificates = rebuildPasskeyServer()->certificates();

    expect($certificates->appliesTo(CeremonyType::Authentication))->toBeTrue();
    expect($certificates->appliesTo(CeremonyType::Registration))->toBeFalse();
});

it('takes default claims from the current request', function () {
    config()->set('passkeys.certificates.enabled', true);

    $request = Request::create('/passkeys/login', 'POST', server: [
        'REMOTE_ADDR' => '203.0.113.7',
        'HTTP_USER_AGENT' => 'Mozilla/5.0 (X11; Linux x86_64)',
        'HTTP_X_REQUEST_ID' => 'req_01HZX',
    ]);
    app()->instance('request', $request);

    expect(rebuildPasskeyServer()->certificates()->claimsFor(BRIDGE_SUBJECT))->toBe([
        'ip' => '203.0.113.7',
        'userAgent' => 'Mozilla/5.0 (X11; Linux x86_64)',
        'requestId' => 'req_01HZX',
    ]);
});

it('leaves out request claims that are absent rather than writing nulls', function () {
    config()->set('passkeys.certificates.enabled', true);
    $request = Request::create('/passkeys/login', 'POST', server: ['REMOTE_ADDR' => '203.0.113.7']);
    // Request::create() supplies "Symfony" as a default user agent.
    $request->headers->remove('User-Agent');
    app()->instance('request', $request);

    expect(rebuildPasskeyServer()->certificates()->claimsFor(BRIDGE_SUBJECT))->toBe(['ip' => '203.0.113.7']);
});

it('uses a configured claims class instead', function () {
    config()->set('passkeys.certificates.enabled', true);
    config()->set('passkeys.certificates.claims', BridgeTestClaims::class);

    expect(rebuildPasskeyServer()->certificates()->claimsFor(BRIDGE_SUBJECT))
        ->toBe(['tenant' => 'acme', 'credential' => 'Y3JlZC1vbmU']);
});

it('delivers by dispatching PasskeyCertificateIssued', function () {
    Event::fake([PasskeyCertificateIssued::class]);
    config()->set('passkeys.certificates.enabled', true);

    $issued = LoginCertificate::issue(...BRIDGE_SUBJECT, issuedAt: '2026-11-13T09:30:00.000Z', nonce: 'AAECAwQFBgcICQoLDA0ODw');
    rebuildPasskeyServer()->certificates()->deliver($issued);

    Event::assertDispatched(
        PasskeyCertificateIssued::class,
        static fn (PasskeyCertificateIssued $event): bool => $event->certificate === $issued,
    );
});

final class BridgeTestClaims
{
    /** @param array<string, string> $subject */
    public function __invoke(Request $request, array $subject): array
    {
        return ['tenant' => 'acme', 'credential' => $subject['credentialId']];
    }
}
