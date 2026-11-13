<?php

declare(strict_types=1);

namespace FancyPasskeys\Support;

use InvalidArgumentException;
use stdClass;

/**
 * The kit's canonical JSON form: **change-council's, copied, not reinvented.**
 *
 * Source: `ChangeCouncil\Support\CanonicalJson` (change-council
 * `src/Support/CanonicalJson.php`), which agrees byte for byte with its Node
 * `council/lib/record.mjs` `canonical()`. The Node twin of this package carries
 * a copy of that function. Change neither copy on its own: the
 * login-certificate fixture is the shared check that the two still agree.
 *
 * - object keys sorted by byte order, recursively; list order kept
 * - no whitespace; `/` and non-ASCII unescaped; U+2028/2029 unescaped
 *   (JSON.stringify does not escape them either)
 * - floats refused: PHP and JavaScript do not print them the same way
 * - an empty PHP array is a list `[]`; an empty object must be a stdClass
 */
final class CanonicalJson
{
    public const FLAGS = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_LINE_TERMINATORS | JSON_THROW_ON_ERROR;

    public static function encode(mixed $value): string
    {
        return json_encode(self::normalise($value), self::FLAGS);
    }

    private static function normalise(mixed $value): mixed
    {
        if (is_float($value)) {
            throw new InvalidArgumentException('Canonical JSON refuses floats; use an integer or a string.');
        }
        if ($value instanceof stdClass) {
            $value = (array) $value;
            if ($value === []) {
                return new stdClass;
            }
        }
        if (! is_array($value)) {
            return $value;
        }
        if (array_is_list($value)) {
            return array_map(self::normalise(...), $value);
        }
        ksort($value, SORT_STRING);
        $out = [];
        foreach ($value as $key => $item) {
            $out[(string) $key] = self::normalise($item);
        }

        return $out;
    }
}
