<?php

declare(strict_types=1);

namespace FancyPasskeys\Support;

/**
 * The signature-counter rule, in one place.
 *
 * `web-auth/webauthn-lib` applies this rule itself during the request ceremony
 * (`CheckCounter` + `ThrowExceptionIfInvalid`) and we do not tighten it. The
 * copy here exists because the non-default counter policies deliberately
 * suppress the library's check — see `PasskeyServer::finishAuthentication()` —
 * and `log-only` still has to be able to say what `reject` would have rejected.
 *
 * Keeping it as a named, tested function rather than an inline comparison is
 * the difference between a rule and a coincidence.
 */
final class CounterCheck
{
    public static function regressed(int $stored, int $new): bool
    {
        /*
         * Both zero → accept.
         *
         * Most synced passkey providers — iCloud Keychain, Google Password
         * Manager — do not implement counters at all and always send 0. A
         * strict `new > stored` rule rejects the majority of real passkeys in
         * the world, which is why this branch exists and why it is not a bug.
         */
        if ($stored === 0 && $new === 0) {
            return false;
        }

        // Otherwise the counter must have strictly advanced. Equal counts as a
        // regression: two devices holding the same private key produce the same
        // value before they produce a lower one.
        return $new <= $stored;
    }
}
