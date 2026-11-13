<?php

declare(strict_types=1);

namespace FancyPasskeys;

use FancyPasskeys\Support\CanonicalJson;
use InvalidArgumentException;
use JsonException;
use stdClass;
use Throwable;

/**
 * Login certificates: an OPTIONAL, canonical record of a successful passkey
 * ceremony, and a token that is the SHA-256 of that record.
 *
 * What it is for: tracing. Log the token beside a request, quote it in a
 * support ticket, store the certificate in an audit table, and later check any
 * of them against the others with {@see self::verify()}.
 *
 * What it is NOT:
 *
 * - **Not a signature, and not a credential.** Anyone holding a certificate can
 *   compute its token; that is what a hash is. A match proves the record and the
 *   token belong together, not who wrote them. Never accept a token as proof of
 *   a session.
 * - **Not our cryptography.** SHA-256 is PHP's `hash()`. No WebAuthn work
 *   happens here; the ceremony was verified before this runs.
 *
 * **Byte-identical with the Node twin** (`login-certificate.ts`). The canonical
 * form is change-council's ({@see CanonicalJson}), and
 * tests/fixtures/login-certificate/vectors.json pins certificate, canonical
 * bytes and token for both runtimes. The claim rules below exist because they
 * are exactly the places the two runtimes would otherwise canonicalise
 * differently.
 */
final class LoginCertificate
{
    public const TYPE = 'fancy-passkeys.login-certificate';

    public const VERSION = 1;

    /**
     * `fplc` = fancy-passkeys login certificate. `v1` binds the certificate
     * schema, the canonical form and SHA-256 together, so changing any of the
     * three is a new prefix, never a silent reinterpretation.
     */
    public const TOKEN_PREFIX = 'fplc_v1_';

    /** JavaScript's Number.MAX_SAFE_INTEGER. Past it, Node cannot represent the value exactly. */
    private const MAX_SAFE_INTEGER = 9007199254740991;

    /**
     * Normalised key fragments that mark a claim as sensitive anywhere in its
     * name. Identical in the Node twin.
     */
    private const SENSITIVE_FRAGMENTS = [
        'password', 'passwd', 'secret', 'token', 'apikey', 'authorization',
        'cookie', 'privatekey', 'sessionid', 'recoverycode',
    ];

    /**
     * Short names that are sensitive only as the WHOLE key. As fragments they
     * would strip harmless keys (`otp` is inside `footprint`, `pin` inside
     * `spin`).
     */
    private const SENSITIVE_NAMES = ['otp', 'totp', 'pin', 'pwd', 'cvv', 'ssn', 'session', 'auth'];

    private function __construct()
    {
    }

    /**
     * Whether a claim key names something that must never be in a certificate.
     *
     * A backstop, not a guarantee: it catches the obvious names and is biased
     * toward stripping (`tokenizer` goes too). An app must not put credentials
     * in a certificate under ANY name.
     */
    public static function isSensitiveKey(string $key): bool
    {
        $normalised = (string) preg_replace('/[^a-z0-9]/', '', strtolower($key));

        if (in_array($normalised, self::SENSITIVE_NAMES, true)) {
            return true;
        }

        foreach (self::SENSITIVE_FRAGMENTS as $fragment) {
            if (str_contains($normalised, $fragment)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Build a certificate, canonicalise it and hash it.
     *
     * Parameter names match the shared fixture's `input` keys, so
     * `LoginCertificate::issue(...$input)` works.
     *
     * @param  mixed  $claims  An associative array or stdClass. Throws
     *                         {@see InvalidArgumentException} for anything with
     *                         no single canonical form across PHP and Node:
     *                         floats, integers beyond 2^53-1, keys that are not
     *                         printable ASCII or are all digits, objects other
     *                         than stdClass, invalid UTF-8.
     */
    public static function issue(
        CeremonyType|string $ceremony,
        string $issuedAt,
        string $nonce,
        string $rpId,
        string $credentialId,
        string $userHandle,
        mixed $claims = [],
    ): IssuedLoginCertificate {
        $ceremony = $ceremony instanceof CeremonyType ? $ceremony->value : $ceremony;

        if (CeremonyType::tryFrom($ceremony) === null) {
            throw new InvalidArgumentException('Login certificate ceremony must be "registration" or "authentication".');
        }

        foreach (['rpId' => $rpId, 'credentialId' => $credentialId, 'userHandle' => $userHandle, 'issuedAt' => $issuedAt] as $field => $value) {
            if ($value === '') {
                throw new InvalidArgumentException(sprintf('Login certificate `%s` must be a non-empty string.', $field));
            }
        }

        if (preg_match('/^[A-Za-z0-9_-]+$/', $nonce) !== 1) {
            throw new InvalidArgumentException('Login certificate `nonce` must be a non-empty base64url string.');
        }

        $stripped = [];
        $cleanClaims = self::cleanObject($claims, 'claims', $stripped, true);

        $certificate = [
            'type' => self::TYPE,
            'version' => self::VERSION,
            'ceremony' => $ceremony,
            'issuedAt' => $issuedAt,
            'nonce' => $nonce,
            'rpId' => $rpId,
            'credentialId' => $credentialId,
            'userHandle' => $userHandle,
            'claims' => $cleanClaims,
        ];

        $canonical = CanonicalJson::encode($certificate);
        sort($stripped, SORT_STRING);

        return new IssuedLoginCertificate($certificate, $canonical, self::tokenFor($canonical), $stripped);
    }

    /**
     * The token for a certificate: an array, a stdClass, or its stored JSON.
     *
     * Nothing is stripped; the certificate is hashed exactly as given. Throws
     * {@see InvalidArgumentException} for a value with no canonical form.
     *
     * Read a stored certificate back with `json_decode($json, false)`, or pass
     * the JSON string itself: an associative decode turns a nested empty object
     * into a list, which has different bytes. (A top-level empty `claims` is
     * always an object by schema, so that one case is handled.)
     */
    public static function token(array|stdClass|string $certificate): string
    {
        if (is_string($certificate)) {
            try {
                $certificate = json_decode($certificate, false, 512, JSON_THROW_ON_ERROR);
            } catch (JsonException $e) {
                throw new InvalidArgumentException('The certificate is not valid JSON.', previous: $e);
            }
        }

        if (is_array($certificate) && array_key_exists('claims', $certificate) && $certificate['claims'] === []) {
            $certificate['claims'] = new stdClass();
        }

        $unused = [];
        $clean = self::cleanObject($certificate, 'certificate', $unused, false);

        return self::tokenFor(CanonicalJson::encode($clean));
    }

    /**
     * Whether `$token` is the token of `$certificate` (array, stdClass, or its
     * stored JSON). Never throws: anything malformed is simply `false`.
     *
     * It says the two belong together, which is all a hash can say.
     */
    public static function verify(mixed $certificate, mixed $token): bool
    {
        if (! is_string($token) || preg_match('/^fplc_v1_[0-9a-f]{64}$/', $token) !== 1) {
            return false;
        }

        try {
            if (is_string($certificate)) {
                $certificate = json_decode($certificate, false, 512, JSON_THROW_ON_ERROR);
            }

            if ($certificate instanceof stdClass) {
                $fields = get_object_vars($certificate);
            } elseif (is_array($certificate)) {
                $fields = $certificate;
            } else {
                return false;
            }

            if (($fields['type'] ?? null) !== self::TYPE || ($fields['version'] ?? null) !== self::VERSION) {
                return false;
            }

            return hash_equals(self::token($certificate), $token);
        } catch (Throwable) {
            return false;
        }
    }

    private static function tokenFor(string $canonical): string
    {
        return self::TOKEN_PREFIX . hash('sha256', $canonical);
    }

    /**
     * Printable ASCII only, so PHP's byte order (`ksort`) and JavaScript's
     * code-unit order agree; and never all digits, because PHP turns "0" or
     * "-1" into an integer key and a run of them from 0 into a LIST. Checked
     * byte by byte rather than with an escaped regex.
     */
    private static function assertKey(int|string $key, string $path): string
    {
        $key = (string) $key;
        $valid = preg_match('/^-?[0-9]+$/', $key) !== 1;

        for ($i = 0, $length = strlen($key); $valid && $i < $length; $i++) {
            $byte = ord($key[$i]);
            $valid = $byte >= 0x20 && $byte <= 0x7E;
        }

        if (! $valid) {
            throw new InvalidArgumentException(sprintf(
                'Login certificate claim key "%s" at %s must be printable ASCII and not all digits.',
                $key,
                $path,
            ));
        }

        return $key;
    }

    /**
     * @param  list<string>  $stripped
     * @return array<string, mixed>|stdClass  stdClass when empty, so it encodes as `{}`.
     */
    private static function cleanObject(mixed $value, string $path, array &$stripped, bool $strip): array|stdClass
    {
        if ($value instanceof stdClass) {
            $entries = get_object_vars($value);
        } elseif (is_array($value) && ($value === [] || ! array_is_list($value))) {
            $entries = $value;
        } else {
            throw new InvalidArgumentException(sprintf('Login certificate %s must be an object (an associative array or stdClass).', $path));
        }

        $out = [];

        foreach ($entries as $key => $item) {
            $key = self::assertKey($key, $path);
            $childPath = $path . '.' . $key;

            if ($strip && self::isSensitiveKey($key)) {
                $stripped[] = $childPath;

                continue;
            }

            $out[$key] = self::cleanValue($item, $childPath, $stripped, $strip);
        }

        return $out === [] ? new stdClass() : $out;
    }

    /** @param list<string> $stripped */
    private static function cleanValue(mixed $value, string $path, array &$stripped, bool $strip): mixed
    {
        if ($value === null || is_bool($value)) {
            return $value;
        }

        if (is_string($value)) {
            if (preg_match('//u', $value) !== 1) {
                throw new InvalidArgumentException(sprintf('Login certificate value at %s is not valid UTF-8.', $path));
            }

            return $value;
        }

        if (is_int($value)) {
            // Exact here, rounded in JavaScript past 2^53-1.
            if ($value > self::MAX_SAFE_INTEGER || $value < -self::MAX_SAFE_INTEGER) {
                throw new InvalidArgumentException(sprintf(
                    'Login certificate value at %s must be an integer within 2^53-1; send big numbers as strings.',
                    $path,
                ));
            }

            return $value;
        }

        if (is_array($value) && array_is_list($value)) {
            $out = [];

            foreach ($value as $index => $item) {
                $out[] = self::cleanValue($item, sprintf('%s[%d]', $path, $index), $stripped, $strip);
            }

            return $out;
        }

        if (is_array($value) || $value instanceof stdClass) {
            return self::cleanObject($value, $path, $stripped, $strip);
        }

        // Floats print differently in PHP and JavaScript; objects other than
        // stdClass have no agreed JSON form.
        throw new InvalidArgumentException(sprintf(
            'Login certificate value at %s must be null, a boolean, an integer, a string, a list or an object; send floats as strings.',
            $path,
        ));
    }
}
