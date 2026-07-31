<?php

declare(strict_types=1);

namespace FancyPasskeys;

use InvalidArgumentException;

/**
 * The account a registration ceremony enrolls a passkey for.
 *
 * `$handle` is the WebAuthn **user handle**: an opaque base64url identifier that
 * every authenticator the user enrolls will store a copy of. It is 32 random
 * bytes and it is never the primary key and never the email — see plan §5.8.
 */
final readonly class PasskeyUser
{
    public function __construct(
        public string $handle,
        public string $name,
        public string $displayName,
    ) {
        if (trim($handle) === '') {
            throw new InvalidArgumentException('A user handle is required.');
        }

        if (trim($name) === '') {
            throw new InvalidArgumentException('A user name is required.');
        }
    }
}
