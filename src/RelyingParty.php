<?php

declare(strict_types=1);

namespace FancyPasskeys;

use InvalidArgumentException;

/**
 * The relying party: who we claim to be, and which origins may speak for us.
 *
 * Everything here is validated in the constructor, on purpose. A relying-party
 * ID that is not a suffix of the configured origins produces a WebAuthn setup
 * where *every* ceremony fails with an opaque browser error, and it fails that
 * way in production, on login, for everyone. Failing at boot instead turns a
 * mystery outage into a stack trace with a line number.
 */
final readonly class RelyingParty
{
    /** @var list<string> */
    private array $origins;

    /**
     * @param  list<string>  $origins  Exact-match allow-list. No wildcards, no regex.
     */
    public function __construct(
        public string $id,
        public string $name,
        array $origins,
        public bool $allowSubdomains = false,
    ) {
        if (trim($id) === '') {
            throw new InvalidArgumentException('The relying party ID cannot be empty.');
        }

        if (trim($name) === '') {
            throw new InvalidArgumentException('The relying party name cannot be empty.');
        }

        $origins = array_values($origins);

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

            // http is only ever acceptable on loopback, where there is no
            // network to intercept. Everywhere else WebAuthn requires a secure
            // context anyway, so an http origin in config is a mistake we can
            // catch here instead of letting the browser catch it silently.
            if ($scheme !== 'https' && ! self::isLoopback($host)) {
                throw new InvalidArgumentException(
                    sprintf('Origin "%s" must use https (only localhost and 127.0.0.1 may use http).', $origin)
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

        $this->origins = $origins;
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

    /** @return list<string> */
    public function origins(): array
    {
        return $this->origins;
    }

    private static function isLoopback(string $host): bool
    {
        return $host === 'localhost' || $host === '127.0.0.1' || $host === '[::1]' || $host === '::1';
    }

    private static function hostMatchesRpId(string $host, string $rpId): bool
    {
        return $host === $rpId || str_ends_with($host, '.' . $rpId);
    }
}
