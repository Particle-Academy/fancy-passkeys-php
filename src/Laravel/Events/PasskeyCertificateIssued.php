<?php

declare(strict_types=1);

namespace FancyPasskeys\Laravel\Events;

use FancyPasskeys\IssuedLoginCertificate;
use Illuminate\Foundation\Events\Dispatchable;

/**
 * A login certificate was issued for a successful passkey ceremony.
 *
 * This is the storage hook: listen for it and write `$certificate->token` and
 * `$certificate->canonical` to your logs or an audit table. The package stores
 * nothing. Fired only when `passkeys.certificates.enabled` is true.
 *
 * It attests that the CEREMONY succeeded. For a sign-in it is dispatched before
 * the session is established, so in the rare case where the credential verifies
 * but its account no longer exists, a certificate is issued and the login still
 * fails.
 */
final class PasskeyCertificateIssued
{
    use Dispatchable;

    public function __construct(public readonly IssuedLoginCertificate $certificate)
    {
    }
}
