<?php

declare(strict_types=1);

namespace FancyPasskeys;

use RuntimeException;
use Throwable;
use Webauthn\Exception\CounterException;
use Webauthn\Exception\InvalidUserHandleException;

/**
 * The only exception this package throws across its public surface.
 *
 * `web-auth/webauthn-lib` throws a family of exceptions whose messages describe
 * exactly which check failed. Those messages are excellent for a log and
 * unacceptable on the wire — they tell an attacker whether a credential exists,
 * which origin was expected, and how far through the ceremony they got. So the
 * upstream throwable is kept as `previous` (log it, ship it to Sentry) and the
 * client sees a code from a closed set plus a message that says nothing.
 */
final class PasskeyException extends RuntimeException
{
    public function __construct(
        public readonly PasskeyErrorCode $errorCode,
        ?Throwable $previous = null,
    ) {
        parent::__construct($errorCode->clientMessage(), 0, $previous);
    }

    public static function challengeExpired(?Throwable $previous = null): self
    {
        return new self(PasskeyErrorCode::ChallengeExpired, $previous);
    }

    public static function challengeNotFound(?Throwable $previous = null): self
    {
        return new self(PasskeyErrorCode::ChallengeNotFound, $previous);
    }

    public static function challengeTypeMismatch(?Throwable $previous = null): self
    {
        return new self(PasskeyErrorCode::ChallengeTypeMismatch, $previous);
    }

    public static function originNotAllowed(?Throwable $previous = null): self
    {
        return new self(PasskeyErrorCode::OriginNotAllowed, $previous);
    }

    public static function rpIdMismatch(?Throwable $previous = null): self
    {
        return new self(PasskeyErrorCode::RpIdMismatch, $previous);
    }

    /**
     * Indistinguishable from {@see self::verificationFailed()} ON THE WIRE —
     * `toArray()` redacts the code, and the status and message already match.
     * The exception keeps the precise code so a log can still tell them apart.
     * See §5.5 of the plan.
     */
    public static function unknownCredential(?Throwable $previous = null): self
    {
        return new self(PasskeyErrorCode::UnknownCredential, $previous);
    }

    public static function credentialAlreadyRegistered(?Throwable $previous = null): self
    {
        return new self(PasskeyErrorCode::CredentialAlreadyRegistered, $previous);
    }

    public static function counterRegressed(?Throwable $previous = null): self
    {
        return new self(PasskeyErrorCode::CounterRegressed, $previous);
    }

    public static function userVerificationRequired(?Throwable $previous = null): self
    {
        return new self(PasskeyErrorCode::UserVerificationRequired, $previous);
    }

    public static function userHandleMismatch(?Throwable $previous = null): self
    {
        return new self(PasskeyErrorCode::UserHandleMismatch, $previous);
    }

    public static function verificationFailed(?Throwable $previous = null): self
    {
        return new self(PasskeyErrorCode::VerificationFailed, $previous);
    }

    public static function invalidResponse(?Throwable $previous = null): self
    {
        return new self(PasskeyErrorCode::InvalidResponse, $previous);
    }

    public static function notSupported(?Throwable $previous = null): self
    {
        return new self(PasskeyErrorCode::NotSupported, $previous);
    }

    /**
     * Normalise anything `web-auth/webauthn-lib` threw.
     *
     * Only two upstream exceptions are worth distinguishing INTERNALLY: a
     * regressed counter (which must flag the credential and fire
     * `PasskeyCloneDetected`) and a user-handle mismatch. Everything else —
     * wrong origin, wrong RP ID hash, missing user presence, bad signature,
     * unparseable attestation — collapses to `verification_failed` right here,
     * because distinguishing them for the caller is exactly the oracle we are
     * trying not to build. The two that survive are redacted again at the wire
     * by {@see PasskeyErrorCode::wireCode()}, so the client sees one answer.
     *
     * The upstream message is never copied into the client-visible message. It
     * survives only as `previous`.
     */
    public static function fromWebauthn(Throwable $e): self
    {
        return match (true) {
            $e instanceof CounterException => self::counterRegressed($e),
            $e instanceof InvalidUserHandleException => self::userHandleMismatch($e),
            default => self::verificationFailed($e),
        };
    }

    /**
     * The status that goes on the wire — the REDACTED code's status.
     *
     * All four codes that redact already answer 401, so this changes nothing
     * today. It routes through `wireCode()` anyway so that adding a redaction
     * for a code with a different status cannot quietly reintroduce the oracle
     * through the status line while the body looks clean.
     */
    public function httpStatus(): int
    {
        return $this->errorCode->wireCode()->httpStatus();
    }

    /**
     * The wire body, identical in shape to the Node twin's.
     *
     * @return array{error: array{code: string, message: string}}
     */
    public function toArray(): array
    {
        // Redacted here and only here — see PasskeyErrorCode::wireCode(). The
        // exception itself keeps the precise code so a log, a listener, or a
        // metric can still tell an unknown credential from a bad signature.
        $wire = $this->errorCode->wireCode();

        return [
            'error' => [
                'code' => $wire->value,
                'message' => $wire->clientMessage(),
            ],
        ];
    }
}
