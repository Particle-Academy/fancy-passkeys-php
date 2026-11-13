<?php

declare(strict_types=1);

namespace FancyPasskeys;

use Closure;
use InvalidArgumentException;

/**
 * The relying party: who we claim to be, and which origins may speak for us.
 *
 * Everything here is validated in the constructor, on purpose. A relying-party
 * ID that is not a suffix of the configured origins produces a WebAuthn setup
 * where *every* ceremony fails with an opaque browser error, and it fails that
 * way in production, on login, for everyone. Failing at boot instead turns a
 * mystery outage into a stack trace with a line number.
 *
 * The origins may instead come from a Closure, for an app whose origin is only
 * known at run time (a desktop app's local server on a port chosen at launch).
 * It is called on EVERY verification, and every list it returns is validated
 * with exactly the construction rules. Mirrors the Node twin's `OriginResolver`.
 *
 * Not `readonly` as a class any more: {@see self::setOrigins()} replaces the
 * allow-list on a live instance. The ID, name and subdomain flag stay readonly.
 */
final class RelyingParty
{
    /** @var list<string>|Closure(): list<string> */
    private array|Closure $origins;

    /**
     * @param  list<string>|Closure(): list<string>  $origins  Exact-match allow-list, or a
     *                                                          Closure returning one. No
     *                                                          wildcards, no regex. A Closure
     *                                                          rather than any `callable`,
     *                                                          because a two-string origin
     *                                                          list can also be a callable
     *                                                          array; wrap a method with
     *                                                          `$this->origins(...)`.
     */
    public function __construct(
        public readonly string $id,
        public readonly string $name,
        array|Closure $origins,
        public readonly bool $allowSubdomains = false,
    ) {
        if (trim($id) === '') {
            throw new InvalidArgumentException('The relying party ID cannot be empty.');
        }

        if (trim($name) === '') {
            throw new InvalidArgumentException('The relying party name cannot be empty.');
        }

        if (self::isIpLiteral(strtolower(trim($id)))) {
            throw new InvalidArgumentException(
                sprintf(
                    'The relying party ID must be a domain name, not an IP address (got "%s"). Browsers '
                    . 'refuse an IP literal as an RP ID; for local development use "localhost" or a '
                    . '"*.localhost" name.',
                    $id
                )
            );
        }

        $this->origins = $origins instanceof Closure ? $origins : $this->validateOrigins($origins);
    }

    /**
     * `web-auth`'s validators take a **host**, not an origin — `example.com`,
     * never `https://example.com`. Passing an origin makes the RP ID hash check
     * fail on every ceremony.
     */
    public function host(): string
    {
        return $this->id;
    }

    /**
     * The allow-list for the verification about to run.
     *
     * A Closure is called on every call, and whatever it returns is validated
     * with the construction rules every time: a value that would have been
     * refused at boot is refused here, and the ceremony never reaches the
     * validator. A Closure that throws propagates; no list is never "allow all".
     *
     * @return list<string>
     */
    public function origins(): array
    {
        $origins = $this->origins;

        return $origins instanceof Closure ? $this->validateOrigins($origins()) : $origins;
    }

    /** Whether the origins come from a Closure rather than a fixed list. */
    public function hasDynamicOrigins(): bool
    {
        return $this->origins instanceof Closure;
    }

    /**
     * Replace the allowed origins: a new fixed list, or a Closure.
     *
     * A fixed list is validated here, and when it is refused the previous
     * configuration stays in place: a failed update must not leave the relying
     * party with no allow-list, or a half-applied one.
     *
     * @param  list<string>|Closure(): list<string>  $origins
     */
    public function setOrigins(array|Closure $origins): void
    {
        $this->origins = $origins instanceof Closure ? $origins : $this->validateOrigins($origins);
    }

    /**
     * The origin rules, in one place: a static list at construction, a list
     * passed to setOrigins(), and every list a Closure returns are held to
     * exactly the same checks.
     *
     * @return list<string>
     */
    private function validateOrigins(mixed $origins): array
    {
        if (! is_array($origins)) {
            throw new InvalidArgumentException('The allowed origins must be a list of origin strings.');
        }

        $origins = array_values($origins);
        $id = $this->id;

        if ($origins === []) {
            throw new InvalidArgumentException(
                'At least one allowed origin is required. Deriving the expected origin from the '
                . 'request is checking the attacker\'s claim against itself.'
            );
        }

        foreach ($origins as $origin) {
            if (! is_string($origin) || trim($origin) === '') {
                throw new InvalidArgumentException('Every allowed origin must be a non-empty string.');
            }

            $parts = parse_url($origin);

            if ($parts === false || ! isset($parts['scheme'], $parts['host'])) {
                throw new InvalidArgumentException(
                    sprintf('"%s" is not a valid origin. Expected something like "https://example.com".', $origin)
                );
            }

            $scheme = strtolower($parts['scheme']);
            $host = strtolower($parts['host']);

            if (self::isIpLiteral($host)) {
                throw new InvalidArgumentException(
                    sprintf(
                        'Origin "%s" has an IP-address host. WebAuthn needs a domain name; for local '
                        . 'development use "localhost" or a "*.localhost" name.',
                        $origin
                    )
                );
            }

            // http is only ever acceptable on localhost and *.localhost, which
            // browsers resolve to loopback and treat as a secure context.
            // Everywhere else WebAuthn requires https anyway, so an http origin
            // in config is a mistake we can catch here instead of letting the
            // browser catch it silently.
            if ($scheme !== 'https' && ! ($scheme === 'http' && self::isLocalhost($host))) {
                throw new InvalidArgumentException(
                    sprintf('Origin "%s" must use https (only localhost and *.localhost hosts may use http).', $origin)
                );
            }

            if (! self::hostMatchesRpId($host, strtolower($id))) {
                throw new InvalidArgumentException(
                    sprintf(
                        'The relying party ID "%s" is not valid for origin "%s". The RP ID must equal the '
                        . 'origin\'s host or be a registrable suffix of it.',
                        $id,
                        $origin
                    )
                );
            }
        }

        /** @var list<string> $origins */
        return $origins;
    }

    /**
     * Whether plain http is tolerated for this host: `localhost` itself, or any
     * `*.localhost` name, matched by LABEL (every label non-empty, the last one
     * exactly `localhost`). `localhost.evil.com` and `evilocalhost` do not
     * qualify.
     *
     * This is what Chromium accepts for WebAuthn, and it is the whole list: an
     * IP literal such as `127.0.0.1` is refused by the browser as an RP ID, so
     * it is refused here too. Mirrored in the Node twin's `isLocalhost()`; both
     * are driven by tests/fixtures/relying-party/origins.json.
     */
    private static function isLocalhost(string $host): bool
    {
        $labels = explode('.', $host);

        foreach ($labels as $label) {
            if ($label === '') {
                return false;
            }
        }

        return end($labels) === 'localhost';
    }

    /**
     * Whether a host is an IP literal, which WebAuthn never accepts as an RP ID.
     *
     * IPv6 is anything bracketed or containing a colon. IPv4 follows the URL
     * standard's "ends in a number" rule (the last label all digits, or `0x`
     * plus hex), because that is exactly when a browser parses a host as IPv4,
     * so short forms such as `127.1` are caught as well as dotted quads.
     */
    private static function isIpLiteral(string $host): bool
    {
        if (str_contains($host, ':') || str_starts_with($host, '[')) {
            return true;
        }

        $labels = explode('.', $host);

        if (count($labels) > 1 && end($labels) === '') {
            array_pop($labels);
        }

        $last = (string) end($labels);

        return preg_match('/^[0-9]+$/', $last) === 1 || preg_match('/^0x[0-9a-f]*$/i', $last) === 1;
    }

    private static function hostMatchesRpId(string $host, string $rpId): bool
    {
        return $host === $rpId || str_ends_with($host, '.' . $rpId);
    }
}
