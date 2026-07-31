<?php

declare(strict_types=1);

namespace FancyPasskeys\Support;

use InvalidArgumentException;

/**
 * Unpadded base64url, the only encoding that crosses the wire in WebAuthn.
 *
 * Everything this package persists — credential IDs, public keys, user handles,
 * challenges — is stored in this form as text. Binary columns are where the
 * encoding bugs live when the same data has to round-trip through two runtimes
 * and three databases.
 */
final class Base64Url
{
    public static function encode(string $raw): string
    {
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }

    public static function decode(string $encoded): string
    {
        $padding = strlen($encoded) % 4;
        $padded = $encoded . ($padding === 0 ? '' : str_repeat('=', 4 - $padding));

        $decoded = base64_decode(strtr($padded, '-_', '+/'), true);

        if ($decoded === false) {
            throw new InvalidArgumentException('Value is not valid base64url.');
        }

        return $decoded;
    }
}
