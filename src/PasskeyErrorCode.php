<?php

declare(strict_types=1);

namespace FancyPasskeys;

/**
 * The closed set of error codes both backends emit.
 *
 * This enum is the PHP half of a contract: `@particle-academy/fancy-passkeys`
 * (Node) exports the identical union, and the React surface switches on these
 * strings without knowing which backend answered. Adding a case here without
 * adding it there breaks the pair.
 */
enum PasskeyErrorCode: string
{
    case ChallengeExpired = 'challenge_expired';
    case ChallengeNotFound = 'challenge_not_found';
    case ChallengeTypeMismatch = 'challenge_type_mismatch';
    case OriginNotAllowed = 'origin_not_allowed';
    case RpIdMismatch = 'rp_id_mismatch';
    case UnknownCredential = 'unknown_credential';
    case CredentialAlreadyRegistered = 'credential_already_registered';
    case CounterRegressed = 'counter_regressed';
    case UserVerificationRequired = 'user_verification_required';
    case UserHandleMismatch = 'user_handle_mismatch';
    case VerificationFailed = 'verification_failed';
    case InvalidResponse = 'invalid_response';
    case NotSupported = 'not_supported';

    /**
     * Every code is a 4xx. A failed ceremony is never a server error: the
     * request was well-formed enough to reach us and the answer is "no".
     * Returning 500 for a bad signature is both a bad UX and a signal that the
     * shape of the failure differs by cause.
     */
    public function httpStatus(): int
    {
        return match ($this) {
            // Authentication genuinely failed. These are the codes an attacker
            // sees, and they must be indistinguishable from one another.
            self::UnknownCredential,
            self::VerificationFailed,
            self::CounterRegressed,
            self::UserVerificationRequired,
            self::UserHandleMismatch => 401,

            // The credential exists and belongs to someone. Conflict, not denial.
            self::CredentialAlreadyRegistered => 409,

            default => 400,
        };
    }

    /**
     * The code a client is allowed to see.
     *
     * True internally, redacted on the wire. Matching messages and statuses are
     * not enough on their own: a distinct `code` is just as good an oracle as a
     * distinct message, and it is the field a client actually branches on.
     * Three codes say something about a credential the server holds —
     *
     * - `unknown_credential` — "no such credential here"
     * - `user_handle_mismatch` — "it exists, but not for this account"
     * - `counter_regressed` — "it exists and we think it was cloned"
     *
     * — and an unauthenticated caller has no business learning any of it. All
     * four collapse to `verification_failed` once they cross the wire.
     *
     * The enum case keeps the precise value for logs, events, and metrics; only
     * {@see PasskeyException::toArray()} redacts. A clone detection still fires
     * `PasskeyCloneDetected` and still stamps `cloned_at` — the app tells the
     * user through a channel that has actually identified them, not through a
     * login error a stranger can read.
     */
    public function wireCode(): self
    {
        return match ($this) {
            self::UnknownCredential,
            self::UserHandleMismatch,
            self::CounterRegressed => self::VerificationFailed,

            default => $this,
        };
    }

    /**
     * The message that goes over the wire.
     *
     * Every redacted code (see {@see self::wireCode()}) must also carry the
     * redacted code's message — redacting the code and leaving a message that
     * still names the real failure would redact nothing. `PasskeyExceptionTest`
     * asserts that every code and its wire code answer with the same message
     * and the same status.
     */
    public function clientMessage(): string
    {
        return match ($this) {
            self::ChallengeExpired => 'That sign-in request expired. Please try again.',
            self::ChallengeNotFound => 'That sign-in request is no longer valid. Please try again.',
            self::ChallengeTypeMismatch => 'That sign-in request is no longer valid. Please try again.',
            self::OriginNotAllowed => 'This site is not allowed to complete that request.',
            self::RpIdMismatch => 'This site is not allowed to complete that request.',
            self::UnknownCredential => 'That passkey could not be verified.',
            self::CredentialAlreadyRegistered => 'That passkey is already registered.',
            self::CounterRegressed => 'That passkey could not be verified. It may have been copied.',
            self::UserVerificationRequired => 'This passkey requires a biometric or PIN check.',
            self::UserHandleMismatch => 'That passkey does not belong to this account.',
            self::VerificationFailed => 'That passkey could not be verified.',
            self::InvalidResponse => 'The passkey response was malformed.',
            self::NotSupported => 'Passkeys are not supported here.',
        };
    }
}
