<?php

declare(strict_types=1);

namespace FancyPasskeys;

use InvalidArgumentException;

/**
 * Every decision a WebAuthn integration lives or dies on, defaulted.
 *
 * These are not knobs to be discovered. They are choices with a documented
 * rationale (plan §5) and a safe default; the constructor exists so an app that
 * genuinely needs a different posture can say so explicitly.
 */
final readonly class PasskeyPolicy
{
    public const USER_VERIFICATION = ['required', 'preferred', 'discouraged'];

    public const RESIDENT_KEY = ['required', 'preferred', 'discouraged'];

    public const ATTESTATION = ['none', 'direct'];

    /**
     * `reject`   — a regressed counter fails the login and stamps `cloned_at`. Default.
     * `log-only` — the login succeeds, but the credential is still flagged.
     * `ignore`   — **this disables clone detection.** Nothing is recorded.
     */
    public const COUNTER_POLICY = ['reject', 'log-only', 'ignore'];

    /**
     * @param  'required'|'preferred'|'discouraged'  $userVerification
     * @param  'required'|'preferred'|'discouraged'  $residentKey
     * @param  'none'|'direct'  $attestation
     * @param  list<int>  $algorithms  COSE identifiers, most-preferred first.
     * @param  'reject'|'log-only'|'ignore'  $counterPolicy
     */
    public function __construct(
        public string $userVerification = 'preferred',
        public string $residentKey = 'preferred',
        public string $attestation = 'none',
        public int $timeoutMs = 60000,
        public int $challengeTtlSeconds = 300,
        public array $algorithms = [-8, -7, -257],
        public string $counterPolicy = 'reject',
    ) {
        self::assertOneOf($userVerification, self::USER_VERIFICATION, 'userVerification');
        self::assertOneOf($residentKey, self::RESIDENT_KEY, 'residentKey');
        self::assertOneOf($attestation, self::ATTESTATION, 'attestation');
        self::assertOneOf($counterPolicy, self::COUNTER_POLICY, 'counterPolicy');

        if ($timeoutMs <= 0) {
            throw new InvalidArgumentException('timeoutMs must be positive.');
        }

        // The TTL is deliberately longer than the browser timeout: a slow but
        // legitimate ceremony (a user hunting for their security key) must not
        // be punished, while a leaked options blob is worthless within minutes.
        if ($challengeTtlSeconds <= 0) {
            throw new InvalidArgumentException('challengeTtlSeconds must be positive.');
        }

        if ($algorithms === []) {
            throw new InvalidArgumentException(
                'At least one COSE algorithm is required — an empty pubKeyCredParams leaves the browser '
                . 'nothing to negotiate.'
            );
        }

        foreach ($algorithms as $algorithm) {
            if (! is_int($algorithm)) {
                throw new InvalidArgumentException('COSE algorithm identifiers must be integers.');
            }
        }
    }

    public static function default(): self
    {
        return new self();
    }

    /** @param list<string> $allowed */
    private static function assertOneOf(string $value, array $allowed, string $field): void
    {
        if (! in_array($value, $allowed, true)) {
            throw new InvalidArgumentException(
                sprintf('%s must be one of: %s. Got "%s".', $field, implode(', ', $allowed), $value)
            );
        }
    }
}
