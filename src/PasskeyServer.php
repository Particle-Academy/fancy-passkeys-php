<?php

declare(strict_types=1);

namespace FancyPasskeys;

use Closure;
use Cose\Algorithm\Manager as AlgorithmManager;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\ECDSA\ES384;
use Cose\Algorithm\Signature\ECDSA\ES512;
use Cose\Algorithm\Signature\EdDSA\Ed25519;
use Cose\Algorithm\Signature\RSA\PS256;
use Cose\Algorithm\Signature\RSA\PS384;
use Cose\Algorithm\Signature\RSA\PS512;
use Cose\Algorithm\Signature\RSA\RS256;
use Cose\Algorithm\Signature\RSA\RS384;
use Cose\Algorithm\Signature\RSA\RS512;
use Cose\Algorithm\Signature\Signature;
use FancyPasskeys\Contracts\ChallengeStore;
use FancyPasskeys\Contracts\CredentialStore;
use FancyPasskeys\Support\Base64Url;
use FancyPasskeys\Support\CounterCheck;
use FancyPasskeys\Support\WireFormat;
use InvalidArgumentException;
use stdClass;
use Symfony\Component\Serializer\Encoder\JsonEncode;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Uid\Uuid;
use Throwable;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\CredentialRecord;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\Exception\CounterException;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\TrustPath\EmptyTrustPath;

/**
 * Both WebAuthn ceremonies, framework-free.
 *
 * This class implements **no cryptography**. Challenge comparison, origin
 * checking, RP ID hashing, UP/UV flags, backup-bit consistency, signature
 * verification and the counter check all live in `web-auth/webauthn-lib`. What
 * lives here is precisely what that library deliberately leaves to the caller,
 * and what almost every hand-rolled integration gets wrong:
 *
 * 1. Issuing, storing, expiring and single-using the challenge.
 * 2. Persisting the credential, and enforcing credential-ID uniqueness.
 * 3. Persisting the counter after every successful assertion.
 * 4. Normalising errors into a closed, wire-safe set.
 *
 * `$now` and `$randomBytes` are injectable so the failure paths — which are the
 * paths that matter — can be tested without sleeping or hoping.
 */
final class PasskeyServer
{
    /**
     * The COSE signature algorithms `web-auth` can verify, by identifier: the
     * library's own classes, selected here, never implemented here.
     *
     * @var array<int, class-string<Signature>>
     */
    private const SIGNATURE_ALGORITHMS = [
        -8 => Ed25519::class,
        -7 => ES256::class,
        -35 => ES384::class,
        -36 => ES512::class,
        -257 => RS256::class,
        -258 => RS384::class,
        -259 => RS512::class,
        -37 => PS256::class,
        -38 => PS384::class,
        -39 => PS512::class,
    ];

    /** 16 bytes of login-certificate nonce. */
    private const CERTIFICATE_NONCE_BYTES = 16;

    private readonly SerializerInterface $serializer;

    private readonly AttestationStatementSupportManager $attestationSupport;

    private readonly AlgorithmManager $algorithms;

    /** @var Closure(): int */
    private readonly Closure $clock;

    /** @var Closure(int): string */
    private readonly Closure $random;

    /**
     * @param  (Closure(): int)|null  $now  Epoch milliseconds.
     * @param  (Closure(int): string)|null  $randomBytes  CSPRNG. Never a timestamp,
     *                                                    counter, or hash of user data.
     * @param  LoginCertificates|null  $certificates  Optional login certificates.
     *                                                Null (the default): none are
     *                                                issued and nothing is called.
     */
    public function __construct(
        public readonly RelyingParty $rp,
        public readonly PasskeyPolicy $policy,
        private readonly ChallengeStore $challenges,
        private readonly CredentialStore $credentials,
        ?Closure $now = null,
        ?Closure $randomBytes = null,
        private readonly ?LoginCertificates $certificates = null,
    ) {
        $this->clock = $now ?? static fn (): int => (int) (microtime(true) * 1000);
        $this->random = $randomBytes ?? static fn (int $length): string => random_bytes($length);

        $this->attestationSupport = AttestationStatementSupportManager::create();
        $this->attestationSupport->add(NoneAttestationStatementSupport::create());

        $this->serializer = (new WebauthnSerializerFactory($this->attestationSupport))->create();

        /*
         * The signature algorithms the assertion check can verify are exactly
         * the ones the policy offers. `CeremonyStepManagerFactory`'s default is
         * ES256 + RS256 only, while the policy offers Ed25519 FIRST — so an
         * authenticator that chose Ed25519 enrolled without complaint (the
         * creation ceremony's CheckAlgorithm accepts it) and could then never
         * sign in. An offered algorithm with no verifier is refused here, at
         * boot, for the same reason.
         */
        $algorithms = AlgorithmManager::create();

        foreach ($this->policy->algorithms as $identifier) {
            $class = self::SIGNATURE_ALGORITHMS[$identifier] ?? null;

            if ($class === null) {
                throw new InvalidArgumentException(sprintf(
                    'COSE algorithm %d is offered by the policy but web-auth/webauthn-lib cannot verify it, so a '
                    . 'credential enrolled with it could never sign in. Supported: %s.',
                    $identifier,
                    implode(', ', array_keys(self::SIGNATURE_ALGORITHMS)),
                ));
            }

            $algorithms->add($class::create());
        }

        $this->algorithms = $algorithms;
    }

    /** The login-certificate configuration, or null when certificates are off. */
    public function certificates(): ?LoginCertificates
    {
        return $this->certificates;
    }

    /**
     * Fresh ceremony steps for ONE verification, built on the origins resolved
     * for it. A Closure-backed relying party is resolved and validated here,
     * every time; an invalid list throws InvalidArgumentException (a
     * configuration error, the app's 500) before any validator exists.
     */
    private function ceremonySteps(): CeremonyStepManagerFactory
    {
        $factory = new CeremonyStepManagerFactory();
        $factory->setAttestationStatementSupportManager($this->attestationSupport);
        $factory->setAlgorithmManager($this->algorithms);
        // Exact-match allow-list. `allowSubdomains` stays false unless the app
        // knowingly turns it on: "ends with example.com" also ends with
        // "notexample.com" in every implementation that gets it wrong.
        // (`setSecuredRelyingPartyId()` is deprecated in 5.2 and is dead code
        // once an explicit origin list is set, so it is deliberately not used.)
        $factory->setAllowedOrigins($this->rp->origins(), $this->rp->allowSubdomains);

        return $factory;
    }

    /**
     * Issue and deliver a login certificate when the host turned them on for
     * this ceremony. Returns null otherwise, having called nothing.
     */
    private function issueCertificate(
        CeremonyType $ceremony,
        string $credentialId,
        string $userHandle,
        array|stdClass $claims,
    ): ?IssuedLoginCertificate {
        $certificates = $this->certificates;

        if ($certificates === null || ! $certificates->appliesTo($ceremony)) {
            return null;
        }

        $subject = [
            'ceremony' => $ceremony->value,
            'rpId' => $this->rp->id,
            'credentialId' => $credentialId,
            'userHandle' => $userHandle,
        ];

        $issued = LoginCertificate::issue(
            ceremony: $ceremony,
            issuedAt: $this->nowIso(),
            nonce: Base64Url::encode(($this->random)(self::CERTIFICATE_NONCE_BYTES)),
            rpId: $this->rp->id,
            credentialId: $credentialId,
            userHandle: $userHandle,
            claims: array_replace(
                $certificates->claimsFor($subject),
                $claims instanceof stdClass ? get_object_vars($claims) : $claims,
            ),
        );

        $certificates->deliver($issued);

        return $issued;
    }

    // -----------------------------------------------------------------------
    // Registration
    // -----------------------------------------------------------------------

    /**
     * @return array{state: string, publicKey: array<string, mixed>}
     */
    public function startRegistration(PasskeyUser $user): array
    {
        $challenge = ($this->random)(32);
        $state = Base64Url::encode(($this->random)(32));

        $this->challenges->put($state, new ChallengeRecord(
            Base64Url::encode($challenge),
            CeremonyType::Registration,
            $user->handle,
            $this->expiryFromNow(),
        ));

        $options = $this->creationOptions(
            $user->handle,
            $user->name,
            $user->displayName,
            $challenge,
            // Every credential this user already holds, so the authenticator
            // itself refuses a duplicate before the network round-trip.
            $this->descriptorsFor($user->handle),
        );

        return [
            'state' => $state,
            'publicKey' => WireFormat::creationOptions($this->serializeOptions($options)),
        ];
    }

    /**
     * @param  array<string, mixed>|string  $response  `RegistrationResponseJSON`.
     * @param  array<string, mixed>|stdClass  $certificateClaims  Claims for the login
     *                                                            certificate, when they
     *                                                            are on. Never credentials.
     * @return array{credential: StoredCredential, summary: array<string, mixed>, certificate: ?IssuedLoginCertificate}
     *
     * @throws PasskeyException
     */
    public function finishRegistration(
        string $state,
        array|string $response,
        ?string $name = null,
        array|stdClass $certificateClaims = [],
    ): array {
        // (1) Pull FIRST — before parsing, before verifying. `pull()` deletes as
        //     it reads, so a replayed response fails here no matter how valid
        //     its signature is. Inverting this ordering (verify, then delete)
        //     makes a captured response replayable forever.
        $challenge = $this->pullChallenge($state, CeremonyType::Registration);

        $credential = $this->deserialize($response);
        $attestation = $credential->response;

        if (! $attestation instanceof AuthenticatorAttestationResponse) {
            throw PasskeyException::invalidResponse();
        }

        $credentialId = Base64Url::encode($credential->rawId);

        // (2) Reject a credential ID already registered to ANYONE. Registered
        //     to another account it is either an attack or a bug, and silently
        //     re-pointing it at this account is account takeover.
        if ($this->credentials->findById($credentialId) !== null) {
            throw PasskeyException::credentialAlreadyRegistered();
        }

        $userHandle = $challenge->userHandle;

        if ($userHandle === null) {
            // A registration challenge without a user handle cannot have been
            // issued by startRegistration(). Treat it as a malformed ceremony.
            throw PasskeyException::invalidResponse();
        }

        // Rebuild the options the browser was handed. Only `challenge`,
        // `pubKeyCredParams`, `attestation` and `user.id` participate in
        // verification — the entity's name and display name are cosmetic and
        // are not carried in the challenge record.
        $options = $this->creationOptions(
            $userHandle,
            $userHandle,
            $userHandle,
            Base64Url::decode($challenge->challenge),
            [],
        );

        // Built per verification on the origins resolved for it. Outside the
        // try: a refused origin list is a configuration error, not a failed
        // ceremony to report to the client.
        $validator = AuthenticatorAttestationResponseValidator::create($this->ceremonySteps()->creationCeremony());

        try {
            // (3) Only now does anything cryptographic happen.
            $record = $validator->check($attestation, $options, $this->rp->host());
        } catch (Throwable $e) {
            throw PasskeyException::fromWebauthn($e);
        }

        $stored = $this->toStoredCredential($record, $name);

        // (4) The store enforces uniqueness again, this time with an index
        //     behind it. The check above races; the index does not.
        $this->credentials->save($stored);

        $certificate = $this->issueCertificate(CeremonyType::Registration, $stored->id, $stored->userHandle, $certificateClaims);

        return ['credential' => $stored, 'summary' => $stored->toSummary(), 'certificate' => $certificate];
    }

    // -----------------------------------------------------------------------
    // Authentication
    // -----------------------------------------------------------------------

    /**
     * @param  string|null  $userHandle  Null for the discoverable (usernameless)
     *                                   flow: `allowCredentials` is empty and the
     *                                   browser shows an account picker.
     * @return array{state: string, publicKey: array<string, mixed>}
     */
    public function startAuthentication(?string $userHandle = null): array
    {
        $challenge = ($this->random)(32);
        $state = Base64Url::encode(($this->random)(32));

        $this->challenges->put($state, new ChallengeRecord(
            Base64Url::encode($challenge),
            CeremonyType::Authentication,
            $userHandle,
            $this->expiryFromNow(),
        ));

        $options = PublicKeyCredentialRequestOptions::create(
            $challenge,
            $this->rp->id,
            $userHandle === null ? [] : $this->descriptorsFor($userHandle),
            $this->policy->userVerification,
            $this->policy->timeoutMs,
        );

        return [
            'state' => $state,
            'publicKey' => WireFormat::requestOptions($this->serializeOptions($options)),
        ];
    }

    /**
     * @param  array<string, mixed>|string  $response  `AuthenticationResponseJSON`.
     * @param  array<string, mixed>|stdClass  $certificateClaims  Claims for the login
     *                                                            certificate, when they
     *                                                            are on. Never credentials.
     * @return array{credential: StoredCredential, summary: array<string, mixed>, userHandle: string, certificate: ?IssuedLoginCertificate}
     *
     * @throws PasskeyException
     */
    public function finishAuthentication(string $state, array|string $response, array|stdClass $certificateClaims = []): array
    {
        // Same pull-first ordering as registration, for the same reason.
        $challenge = $this->pullChallenge($state, CeremonyType::Authentication);

        $credential = $this->deserialize($response);
        $assertion = $credential->response;

        if (! $assertion instanceof AuthenticatorAssertionResponse) {
            throw PasskeyException::invalidResponse();
        }

        $credentialId = Base64Url::encode($credential->rawId);
        $stored = $this->credentials->findById($credentialId);

        if ($stored === null) {
            // Indistinguishable from a bad signature, by design: a distinct
            // "we have never seen that credential" is an existence oracle.
            throw PasskeyException::unknownCredential();
        }

        if ($challenge->userHandle !== null && ! hash_equals($stored->userHandle, $challenge->userHandle)) {
            throw PasskeyException::userHandleMismatch();
        }

        $options = PublicKeyCredentialRequestOptions::create(
            Base64Url::decode($challenge->challenge),
            $this->rp->id,
            $challenge->userHandle === null ? [] : $this->descriptorsFor($challenge->userHandle),
            $this->policy->userVerification,
            $this->policy->timeoutMs,
        );

        $record = $this->toCredentialRecord($stored);
        $storedCounter = $stored->signCount;

        // Counter policy. `CheckCounter` runs inside the library and only fires
        // when either counter is non-zero, so the way to suppress it without
        // forking the ceremony is to hand it a stored counter of 0: the check
        // is then either skipped (response also 0) or trivially satisfied
        // (response > 0). We keep `$storedCounter` and do the comparison
        // ourselves afterwards, so `log-only` still records what `reject` would
        // have rejected.
        $suppressLibraryCounterCheck = $this->policy->counterPolicy !== 'reject';

        if ($suppressLibraryCounterCheck) {
            $record->counter = 0;
        }

        // Per verification, on the origins resolved for it; see finishRegistration.
        $validator = AuthenticatorAssertionResponseValidator::create($this->ceremonySteps()->requestCeremony());

        try {
            $verified = $validator->check(
                $record,
                $assertion,
                $options,
                $this->rp->host(),
                $challenge->userHandle === null ? null : Base64Url::decode($challenge->userHandle),
            );
        } catch (CounterException $e) {
            // Only reachable under the `reject` policy. Flag before rethrowing:
            // the counter is a one-shot detector, and a login that merely fails
            // throws the signal away — the next attempt from the real device
            // advances the counter and the evidence is gone.
            $this->credentials->flagCloned($stored->id, $this->nowIso());

            throw PasskeyException::counterRegressed($e);
        } catch (Throwable $e) {
            throw PasskeyException::fromWebauthn($e);
        }

        $newCounter = $verified->counter;

        if ($suppressLibraryCounterCheck && CounterCheck::regressed($storedCounter, $newCounter)) {
            if ($this->policy->counterPolicy === 'log-only') {
                $this->credentials->flagCloned($stored->id, $this->nowIso());
            }
            // 'ignore' deliberately records nothing. This is what "disables
            // clone detection" means, in those words.
        }

        // ALWAYS persist, including when the counter is 0. Authenticators that
        // do not implement counters (most synced passkey providers) always send
        // 0, and skipping the write for them would be harmless — but skipping
        // it in general is the single most common way the clone detector is
        // silently defeated: the stored value never advances, so every future
        // comparison is against 0 and the check can never fire. One
        // unconditional write is cheaper than a conditional one that is wrong.
        $usedAt = $this->nowIso();
        $this->credentials->updateAfterAuthentication($stored->id, $newCounter, $usedAt);

        $updated = $stored->with(signCount: $newCounter, lastUsedAt: $usedAt);

        // Only now, after the ceremony verified and its outcome is persisted.
        $certificate = $this->issueCertificate(CeremonyType::Authentication, $updated->id, $updated->userHandle, $certificateClaims);

        return [
            'credential' => $updated,
            'summary' => $updated->toSummary(),
            'userHandle' => $updated->userHandle,
            'certificate' => $certificate,
        ];
    }

    /** @return list<array<string, mixed>> */
    public function listPasskeys(string $userHandle): array
    {
        return array_map(
            static fn (StoredCredential $c): array => $c->toSummary(),
            $this->credentials->findByUserHandle($userHandle),
        );
    }

    // -----------------------------------------------------------------------
    // Internals
    // -----------------------------------------------------------------------

    private function pullChallenge(string $state, CeremonyType $expected): ChallengeRecord
    {
        $record = $this->challenges->pull($state);

        if ($record === null) {
            throw PasskeyException::challengeNotFound();
        }

        // A conforming store already dropped expired records, but a store is
        // consumer-supplied and its clock is not ours. This check is the
        // authoritative one.
        if ($record->isExpired(($this->clock)())) {
            throw PasskeyException::challengeExpired();
        }

        if ($record->type !== $expected) {
            throw PasskeyException::challengeTypeMismatch();
        }

        return $record;
    }

    /** @param array<string, mixed>|string $response */
    private function deserialize(array|string $response): PublicKeyCredential
    {
        try {
            $json = is_string($response)
                ? $response
                : json_encode($response, JSON_THROW_ON_ERROR);

            $credential = $this->serializer->deserialize($json, PublicKeyCredential::class, 'json');
        } catch (Throwable $e) {
            throw PasskeyException::invalidResponse($e);
        }

        if (! $credential instanceof PublicKeyCredential) {
            throw PasskeyException::invalidResponse();
        }

        return $credential;
    }

    /**
     * @param  list<PublicKeyCredentialDescriptor>  $excludeCredentials
     */
    private function creationOptions(
        string $userHandle,
        string $name,
        string $displayName,
        string $challenge,
        array $excludeCredentials,
    ): PublicKeyCredentialCreationOptions {
        return PublicKeyCredentialCreationOptions::create(
            $this->rpEntity(),
            // Name first, id second. Reversed, the ceremony still works and the
            // user sees a base64 blob as their account name forever.
            PublicKeyCredentialUserEntity::create($name, Base64Url::decode($userHandle), $displayName),
            $challenge,
            // Not auto-populated when empty — an empty list leaves the browser
            // no algorithm to negotiate.
            $this->pubKeyCredParams(),
            new AuthenticatorSelectionCriteria(
                null,
                $this->policy->userVerification,
                $this->policy->residentKey,
            ),
            $this->policy->attestation,
            $excludeCredentials,
            $this->policy->timeoutMs,
        );
    }

    /**
     * `rp.name` is a required W3C field — it is the name the browser shows in
     * the enrollment prompt — but 5.3 deprecated the `$name` *constructor
     * parameter* on the shared entity base class and gave
     * `PublicKeyCredentialRpEntity` no replacement for it. Assigning the
     * (public, mutable) property afterwards is exactly what
     * `PublicKeyCredentialUserEntity` does internally, and it emits the same
     * payload without firing a deprecation on every single ceremony.
     */
    private function rpEntity(): PublicKeyCredentialRpEntity
    {
        $entity = PublicKeyCredentialRpEntity::create('', $this->rp->id);
        $entity->name = $this->rp->name;

        return $entity;
    }

    /** @return list<PublicKeyCredentialParameters> */
    private function pubKeyCredParams(): array
    {
        return array_map(
            static fn (int $alg): PublicKeyCredentialParameters => PublicKeyCredentialParameters::create(
                PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                $alg,
            ),
            $this->policy->algorithms,
        );
    }

    /** @return list<PublicKeyCredentialDescriptor> */
    private function descriptorsFor(string $userHandle): array
    {
        return array_map(
            static fn (StoredCredential $c): PublicKeyCredentialDescriptor => PublicKeyCredentialDescriptor::create(
                PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                Base64Url::decode($c->id),
                $c->transports,
            ),
            $this->credentials->findByUserHandle($userHandle),
        );
    }

    /** @return array<string, mixed> */
    private function serializeOptions(object $options): array
    {
        $json = $this->serializer->serialize($options, 'json', [
            // Without SKIP_NULL_VALUES the payload carries nulls the browser
            // rejects outright.
            AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
            JsonEncode::OPTIONS => JSON_THROW_ON_ERROR,
        ]);

        $decoded = json_decode($json, true, 512, JSON_THROW_ON_ERROR);

        if (! is_array($decoded)) {
            throw new InvalidArgumentException('The serializer produced a non-object payload.');
        }

        /** @var array<string, mixed> $decoded */
        return $decoded;
    }

    private function toStoredCredential(CredentialRecord $record, ?string $name): StoredCredential
    {
        return new StoredCredential(
            id: Base64Url::encode($record->publicKeyCredentialId),
            publicKey: Base64Url::encode($record->credentialPublicKey),
            userHandle: Base64Url::encode($record->userHandle),
            signCount: $record->counter,
            transports: array_values($record->transports),
            aaguid: $record->aaguid->toRfc4122(),
            backedUp: $record->backupStatus,
            backupEligible: $record->backupEligible,
            uvInitialized: $record->uvInitialized,
            // Stored, never trusted. Making a trust decision from this needs
            // the FIDO Metadata Service and a revocation story — see plan §5.7.
            attestationFormat: $record->attestationType,
            name: $name,
            createdAt: $this->nowIso(),
        );
    }

    private function toCredentialRecord(StoredCredential $stored): CredentialRecord
    {
        return CredentialRecord::create(
            Base64Url::decode($stored->id),
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            $stored->transports,
            $stored->attestationFormat ?? 'none',
            EmptyTrustPath::create(),
            $stored->aaguid === null ? Uuid::fromString(Uuid::NIL) : Uuid::fromString($stored->aaguid),
            Base64Url::decode($stored->publicKey),
            Base64Url::decode($stored->userHandle),
            $stored->signCount,
            null,
            $stored->backupEligible,
            $stored->backedUp,
            $stored->uvInitialized,
        );
    }

    private function expiryFromNow(): int
    {
        return ($this->clock)() + $this->policy->challengeTtlSeconds * 1000;
    }

    /** ISO-8601 with milliseconds, matching the Node twin's `toISOString()`. */
    private function nowIso(): string
    {
        $ms = ($this->clock)();

        return gmdate('Y-m-d\TH:i:s', intdiv($ms, 1000)) . sprintf('.%03dZ', $ms % 1000);
    }
}
