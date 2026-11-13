<?php

declare(strict_types=1);

namespace FancyPasskeys;

use Closure;
use InvalidArgumentException;
use stdClass;

/**
 * Turns login certificates ON for a {@see PasskeyServer}. Without one (the
 * default) none are issued, nothing is called and nothing is stored. Mirrors
 * the Node twin's `LoginCertificateOptions`.
 */
final readonly class LoginCertificates
{
    /** @var list<CeremonyType> */
    public array $ceremonies;

    /**
     * - `$ceremonies`: which ceremonies issue one. Default: both.
     * - `$claims`: host-wide default claims (app name, build, the current
     *   request's IP), called with the ceremony facts. Per-call claims win over
     *   these at the top level.
     * - `$deliver`: hands the certificate and token to the app's storage or
     *   logs. The package keeps nothing. A throw fails the call, so an app that
     *   asked for an audit record gets no silent gaps.
     *
     * @param  list<CeremonyType|string>  $ceremonies
     * @param  (Closure(array{ceremony: string, rpId: string, credentialId: string, userHandle: string}): (array<string, mixed>|stdClass))|null  $claims
     * @param  (Closure(IssuedLoginCertificate): void)|null  $deliver
     */
    public function __construct(
        array $ceremonies = [CeremonyType::Registration, CeremonyType::Authentication],
        private ?Closure $claims = null,
        private ?Closure $deliver = null,
    ) {
        $resolved = [];

        foreach ($ceremonies as $ceremony) {
            $type = $ceremony instanceof CeremonyType ? $ceremony : CeremonyType::tryFrom((string) $ceremony);

            if ($type === null) {
                throw new InvalidArgumentException(sprintf(
                    'Unknown login-certificate ceremony "%s"; expected "registration" or "authentication".',
                    is_scalar($ceremony) ? (string) $ceremony : get_debug_type($ceremony),
                ));
            }

            $resolved[] = $type;
        }

        $this->ceremonies = $resolved;
    }

    public function appliesTo(CeremonyType $ceremony): bool
    {
        return in_array($ceremony, $this->ceremonies, true);
    }

    /**
     * The host's default claims for this ceremony, or `[]` without a provider.
     *
     * @param  array{ceremony: string, rpId: string, credentialId: string, userHandle: string}  $subject
     * @return array<string, mixed>
     */
    public function claimsFor(array $subject): array
    {
        if ($this->claims === null) {
            return [];
        }

        $claims = ($this->claims)($subject);

        return $claims instanceof stdClass ? get_object_vars($claims) : (array) $claims;
    }

    public function deliver(IssuedLoginCertificate $issued): void
    {
        if ($this->deliver !== null) {
            ($this->deliver)($issued);
        }
    }
}
