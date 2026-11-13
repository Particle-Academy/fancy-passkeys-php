<?php

declare(strict_types=1);

namespace FancyPasskeys\Tests\Support;

use CBOR\ByteStringObject;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\TextStringObject;
use CBOR\UnsignedIntegerObject;
use FancyPasskeys\Support\Base64Url;

/**
 * A software authenticator, for TESTS ONLY, that completes real ceremonies.
 *
 * Everything else in this suite stops before the signature check, because a
 * verified response needs a key. Login certificates are issued only AFTER a
 * ceremony succeeds, so testing them honestly needs a ceremony that succeeds —
 * through the real `web-auth/webauthn-lib` validators, not a faked result.
 *
 * The key is Ed25519 from PHP's built-in sodium extension. This is a test
 * fixture playing the authenticator's part; `src/` still contains no
 * cryptography, and nothing here is reachable from the package.
 *
 * - Registration uses `none` attestation, so it needs no signature at all: an
 *   authenticator-data blob carrying the credential id and its COSE public key.
 * - Authentication signs `authenticatorData || SHA-256(clientDataJSON)`, which
 *   is the whole of what a real authenticator signs.
 */
final class SoftwareAuthenticator
{
    private readonly string $keyPair;

    public function __construct(
        public readonly string $rawCredentialId = 'software-authenticator-cred-01',
        private readonly string $rpId = 'example.com',
        private readonly string $origin = 'https://example.com',
        private int $counter = 0,
    ) {
        $this->keyPair = sodium_crypto_sign_keypair();
    }

    public function credentialId(): string
    {
        return Base64Url::encode($this->rawCredentialId);
    }

    /** @return array<string, mixed> `RegistrationResponseJSON` */
    public function register(string $challenge): array
    {
        $attestedCredentialData = str_repeat("\0", 16)
            . pack('n', strlen($this->rawCredentialId))
            . $this->rawCredentialId
            . $this->coseKey();

        // UP | UV | AT. Counter 0 at enrollment.
        $authData = hash('sha256', $this->rpId, true) . chr(0x01 | 0x04 | 0x40) . pack('N', 0)
            . $attestedCredentialData;

        $attestationObject = MapObject::create()
            ->add(TextStringObject::create('fmt'), TextStringObject::create('none'))
            ->add(TextStringObject::create('attStmt'), MapObject::create())
            ->add(TextStringObject::create('authData'), ByteStringObject::create($authData));

        return [
            'id' => $this->credentialId(),
            'rawId' => $this->credentialId(),
            'type' => 'public-key',
            'response' => [
                'clientDataJSON' => Base64Url::encode($this->clientData('webauthn.create', $challenge)),
                'attestationObject' => Base64Url::encode((string) $attestationObject),
                'transports' => ['internal'],
            ],
            'clientExtensionResults' => [],
        ];
    }

    /** @return array<string, mixed> `AuthenticationResponseJSON` */
    public function assert(string $challenge, ?string $userHandle = null): array
    {
        $this->counter++;

        // UP | UV, no attested credential data.
        $authData = hash('sha256', $this->rpId, true) . chr(0x01 | 0x04) . pack('N', $this->counter);
        $clientData = $this->clientData('webauthn.get', $challenge);

        $signature = sodium_crypto_sign_detached(
            $authData . hash('sha256', $clientData, true),
            sodium_crypto_sign_secretkey($this->keyPair),
        );

        $response = [
            'clientDataJSON' => Base64Url::encode($clientData),
            'authenticatorData' => Base64Url::encode($authData),
            'signature' => Base64Url::encode($signature),
        ];

        if ($userHandle !== null) {
            $response['userHandle'] = $userHandle;
        }

        return [
            'id' => $this->credentialId(),
            'rawId' => $this->credentialId(),
            'type' => 'public-key',
            'response' => $response,
            'clientExtensionResults' => [],
        ];
    }

    /** COSE OKP key: kty 1 (OKP), alg -8 (EdDSA), crv 6 (Ed25519), x. */
    private function coseKey(): string
    {
        return (string) MapObject::create()
            ->add(UnsignedIntegerObject::create(1), UnsignedIntegerObject::create(1))
            ->add(UnsignedIntegerObject::create(3), NegativeIntegerObject::create(-8))
            ->add(NegativeIntegerObject::create(-1), UnsignedIntegerObject::create(6))
            ->add(NegativeIntegerObject::create(-2), ByteStringObject::create(sodium_crypto_sign_publickey($this->keyPair)));
    }

    private function clientData(string $type, string $challenge): string
    {
        return json_encode([
            'type' => $type,
            'challenge' => $challenge,
            'origin' => $this->origin,
            'crossOrigin' => false,
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }
}
