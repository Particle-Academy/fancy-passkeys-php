<?php

declare(strict_types=1);

namespace FancyPasskeys;

/**
 * What issuing a login certificate produces. Mirrors the Node twin's
 * `IssuedLoginCertificate`.
 */
final readonly class IssuedLoginCertificate
{
    /**
     * @param  array<string, mixed>  $certificate  The v1 certificate. An empty
     *                                             object inside it is a stdClass,
     *                                             so it re-encodes as `{}`.
     * @param  string  $canonical  The exact bytes that were hashed. Store THIS
     *                             if you store the certificate.
     * @param  string  $token  `fplc_v1_` + 64 lowercase hex characters.
     * @param  list<string>  $stripped  Paths of claims removed as known-sensitive
     *                                  (`claims.device.token`), sorted. Not part
     *                                  of the certificate.
     */
    public function __construct(
        public array $certificate,
        public string $canonical,
        public string $token,
        public array $stripped,
    ) {
    }

    /**
     * @return array{certificate: array<string, mixed>, canonical: string, token: string, stripped: list<string>}
     */
    public function toArray(): array
    {
        return [
            'certificate' => $this->certificate,
            'canonical' => $this->canonical,
            'token' => $this->token,
            'stripped' => $this->stripped,
        ];
    }
}
