<?php

declare(strict_types=1);

namespace FancyPasskeys\Tests\Support;

use CBOR\ByteStringObject;
use CBOR\MapObject;
use CBOR\TextStringObject;
use FancyPasskeys\Support\Base64Url;

/**
 * Syntactically valid, cryptographically worthless ceremony responses.
 *
 * Every failure this package is responsible for — replayed challenge, expired
 * challenge, ceremony-type mismatch, unknown credential, cross-user reuse,
 * user-handle mismatch, disallowed origin — is decided *before* any signature
 * is checked. That is the whole point of the ordering, and it is what makes
 * these paths testable without a real authenticator: a response only has to
 * parse for the check under test to fire.
 *
 * Nothing here computes a signature or a key. A test that needs a *verified*
 * response needs a real authenticator, and none of the tests in this repo do.
 */
final class Ceremony
{
    /**
     * @param  array<string, mixed>  $overrides  Merged into the clientData object.
     * @return array<string, mixed> `RegistrationResponseJSON`
     */
    public static function registrationResponse(
        string $challenge,
        string $rawId,
        string $origin = 'https://example.com',
        array $overrides = [],
    ): array {
        return [
            'id' => Base64Url::encode($rawId),
            'rawId' => Base64Url::encode($rawId),
            'type' => 'public-key',
            'response' => [
                'clientDataJSON' => self::clientData('webauthn.create', $challenge, $origin, $overrides),
                'attestationObject' => self::attestationObject(),
                'transports' => ['internal'],
            ],
            'clientExtensionResults' => [],
        ];
    }

    /**
     * @param  array<string, mixed>  $overrides
     * @return array<string, mixed> `AuthenticationResponseJSON`
     */
    public static function authenticationResponse(
        string $challenge,
        string $rawId,
        ?string $userHandle = null,
        string $origin = 'https://example.com',
        int $signCount = 0,
        array $overrides = [],
    ): array {
        $response = [
            'clientDataJSON' => self::clientData('webauthn.get', $challenge, $origin, $overrides),
            'authenticatorData' => Base64Url::encode(self::authenticatorData($signCount)),
            'signature' => Base64Url::encode('not-a-real-signature'),
        ];

        if ($userHandle !== null) {
            $response['userHandle'] = $userHandle;
        }

        return [
            'id' => Base64Url::encode($rawId),
            'rawId' => Base64Url::encode($rawId),
            'type' => 'public-key',
            'response' => $response,
            'clientExtensionResults' => [],
        ];
    }

    /** @param array<string, mixed> $overrides */
    private static function clientData(string $type, string $challenge, string $origin, array $overrides): string
    {
        return Base64Url::encode(json_encode(array_merge([
            'type' => $type,
            'challenge' => $challenge,
            'origin' => $origin,
            'crossOrigin' => false,
        ], $overrides), JSON_THROW_ON_ERROR));
    }

    /**
     * 32-byte RP ID hash, flags (UP|UV, no attested credential data), counter.
     * The AT bit is deliberately clear: with it set the parser would demand a
     * COSE public key, and none of these tests get far enough to need one.
     */
    private static function authenticatorData(int $signCount): string
    {
        return hash('sha256', 'example.com', true) . chr(0x05) . pack('N', $signCount);
    }

    private static function attestationObject(): string
    {
        $object = MapObject::create()
            ->add(TextStringObject::create('fmt'), TextStringObject::create('none'))
            ->add(TextStringObject::create('attStmt'), MapObject::create())
            ->add(TextStringObject::create('authData'), ByteStringObject::create(self::authenticatorData(0)));

        return Base64Url::encode((string) $object);
    }
}
