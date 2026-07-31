# Fancy Passkeys (PHP)

**Passkey (WebAuthn) login for PHP.** A framework-free core plus a Laravel
bridge that augments Fortify instead of replacing it.

This package implements **no WebAuthn cryptography**. CBOR decoding, COSE key
parsing, ASN.1, attestation chains, RP-ID hashing and `clientDataJSON`
canonicalisation all live in [`web-auth/webauthn-lib`][webauthn-lib] ^5.3, which
is the de-facto standard PHP implementation and the one the Symfony bundle is
built on. What this package owns is precisely what that library deliberately
leaves to the caller — and what almost every hand-rolled integration gets wrong:

1. **Issuing, storing, expiring and single-using the challenge.**
2. **Persisting the credential**, and enforcing credential-ID uniqueness.
3. **Persisting the counter** after every successful assertion.
4. **Normalising errors** into a closed, wire-safe set.

It has a Node twin, [`@particle-academy/fancy-passkeys`][js-twin], which emits
an equal payload for the same inputs — deep-equal once parsed, since key order
is not part of the contract — so one React surface works against either backend.
`tests/WireParityTest.php` holds both sides to fixtures generated from the real
`@simplewebauthn/server`.

[webauthn-lib]: https://github.com/web-auth/webauthn-framework
[js-twin]: https://www.npmjs.com/package/@particle-academy/fancy-passkeys

---

## Install

```bash
composer require particle-academy/fancy-passkeys
```

Requires PHP 8.2+. Laravel (11.x–13.x) and Fortify are **suggests**, not
requirements — the core runs without them.

---

## Laravel quickstart

### 1. Publish and migrate

```bash
php artisan vendor:publish --tag=passkeys-config
php artisan vendor:publish --tag=passkeys-migrations   # optional; they auto-load
php artisan migrate
```

Two migrations land: `passkey_credentials` (one row per passkey, with a
**unique index on `credential_id`**), and a nullable unique
`passkey_user_handle` column on your users table.

### 2. Configure the relying party

```dotenv
PASSKEYS_RP_ID=example.com
PASSKEYS_RP_NAME="Example App"
PASSKEYS_ORIGINS=https://example.com,https://www.example.com
```

The RP ID must be the host of every configured origin, or a registrable suffix
of it. If it is not, `RelyingParty` throws **at boot**, not on the first login —
a misconfigured relying party otherwise surfaces as every ceremony in production
failing with an opaque browser error and no server-side signal at all.

For local development: `PASSKEYS_RP_ID=localhost` and
`PASSKEYS_ORIGINS=http://localhost:5173`. `http://` is accepted only on
`localhost` / `127.0.0.1`.

### 3. Add the trait

```php
use FancyPasskeys\Laravel\Concerns\HasPasskeys;

class User extends Authenticatable
{
    use HasPasskeys;
}
```

That adds a `passkeys()` relation and `passkeyUserHandle()`, which mints 32
random bytes on first use and persists them.

### 4. The four routes

They are registered automatically in their own group (prefix `passkeys`,
middleware `web`), and **no Fortify route is touched, modified, or
re-registered**.

```
POST /passkeys/register/options    auth required
  → 200 { "state": "<opaque>", "publicKey": PublicKeyCredentialCreationOptionsJSON }

POST /passkeys/register            auth required
  body { "state": "<opaque>", "name"?: string, "response": RegistrationResponseJSON }
  → 201 { "credential": PasskeySummaryJSON }

POST /passkeys/login/options       guest
  body { "email"?: string }        // omitted ⇒ discoverable / usernameless
  → 200 { "state": "<opaque>", "publicKey": PublicKeyCredentialRequestOptionsJSON }

POST /passkeys/login               guest
  body { "state": "<opaque>", "response": AuthenticationResponseJSON }
  → 200 { "user": {...}, "credential": PasskeySummaryJSON }
```

Errors, from every endpoint:

```json
{ "error": { "code": "challenge_expired", "message": "That sign-in request expired. Please try again." } }
```

All four are POST, all four are CSRF-protected (the package does **not** exempt
itself), and all four answer `Cache-Control: no-store`.

### 5. The browser half

The ceremony wrappers live in
[`@particle-academy/fancy-passkeys-ui/client`][ui] — a React-free subpath — so a
non-React frontend never installs React to use them. Roughly:

```ts
const { state, publicKey } = await post('/passkeys/login/options', {});
const response = await startAuthentication({ optionsJSON: publicKey });
await post('/passkeys/login', { state, response });
```

[ui]: https://www.npmjs.com/package/@particle-academy/fancy-passkeys-ui

### Fitting an existing Fortify app

**Passkeys are a parallel path to the same session, never a fork of the auth
stack.** Password login, registration, reset and 2FA keep working untouched.

- **Guard.** Login authenticates on `config('passkeys.guard')`, which defaults
  to `config('fortify.guard')`, which defaults to `web`.
- **Login event.** `StatefulGuard::login()` dispatches
  `Illuminate\Auth\Events\Login` itself — the same way Fortify produces it — so
  anything already listening (analytics, gamification, audit) cannot tell a
  passkey session from a password one. The package deliberately does **not**
  dispatch `Login` a second time; it would double-count every listener. It adds
  `FancyPasskeys\Laravel\Events\PasskeyAuthenticated` on top.
- **Session.** Regenerated after login, as Fortify's
  `PrepareAuthenticatedSession` does.
- **Rate limiting.** If Fortify's `login` limiter is registered, the passkey
  login path reuses it, so an app's existing throttle covers both. Otherwise the
  package registers its own `passkeys` limiter. An unthrottled passkey endpoint
  beside a throttled password endpoint is a bypass, not a feature.
- **Two-factor.** Passkey login does **not** skip a configured 2FA challenge.
  `Passkeys::satisfiesTwoFactor($credential)` reports whether the ceremony was
  strong enough to stand in for one (UV required *and* performed) and stops
  there. Deciding to act on that is the app's call, not ours.

Events you can listen to:

| Event | When |
|---|---|
| `PasskeyRegistered` | A credential was enrolled |
| `PasskeyAuthenticated` | A passkey login succeeded |
| `PasskeyCloneDetected` | A signature counter regressed |

---

## Framework-free usage

No Laravel, no container, no config files:

```php
use FancyPasskeys\{PasskeyServer, PasskeyPolicy, PasskeyUser, RelyingParty};

$server = new PasskeyServer(
    new RelyingParty('example.com', 'Example App', ['https://example.com']),
    PasskeyPolicy::default(),
    $challengeStore,   // your ChallengeStore
    $credentialStore,  // your CredentialStore
);

// Registration
['state' => $state, 'publicKey' => $options] = $server->startRegistration(
    new PasskeyUser($userHandle, 'ada@example.com', 'Ada Lovelace')
);
['credential' => $credential] = $server->finishRegistration($state, $responseJson, 'MacBook Touch ID');

// Authentication (discoverable: pass no handle)
['state' => $state, 'publicKey' => $options] = $server->startAuthentication();
['userHandle' => $handle] = $server->finishAuthentication($state, $responseJson);
```

`$now` and `$randomBytes` are injectable constructor arguments, so the failure
paths — which are the paths that matter — can be tested deterministically.

Nothing in `src/` imports `Illuminate\*`. Everything Laravel lives under
`src/Laravel/`.

### The store contracts

Two interfaces, and the interesting half is `pull()`.

```php
interface ChallengeStore
{
    public function put(string $handle, ChallengeRecord $record): void;
    public function pull(string $handle): ?ChallengeRecord;   // reads AND deletes
}
```

`pull()` must delete as it reads, and must treat an expired record as absent.
This is the entire anti-replay mechanism: the finish handlers pull **before**
they verify, so a replayed response fails at "no such challenge" no matter how
valid its signature is.

```php
interface CredentialStore
{
    public function findById(string $id): ?StoredCredential;
    public function findByUserHandle(string $userHandle): array;
    public function save(StoredCredential $credential): void;              // throws on a duplicate ID
    public function updateAfterAuthentication(string $id, int $signCount, string $lastUsedAt): void;
    public function flagCloned(string $id, string $clonedAt): void;
    public function delete(string $id): void;
}
```

`web-auth/webauthn-lib` v5 removed `PublicKeyCredentialSourceRepository`
entirely — lookup is the caller's job now, which is why this interface exists.

Ship-ready implementations: `Support\InMemoryChallengeStore` /
`Support\InMemoryCredentialStore` (one process; tests and scripts), and
`Laravel\CacheChallengeStore` / `Laravel\EloquentCredentialStore`.

---

## Security defaults

Every row is a decision with a rationale and a test — not an option you are
expected to discover.

| Decision | Default | Why |
|---|---|---|
| **Challenge size** | 32 CSPRNG bytes | Never a timestamp, counter, or hash of user data. |
| **Challenge lifetime** | 300 s | Longer than the 60 s browser timeout so a slow but legitimate ceremony is not punished; short enough that a leaked options blob is worthless. |
| **Challenge use** | **Single**, consumed by `pull()` | Read-and-delete in one operation, *before* verification. Read-then-verify-then-delete makes a captured valid response replayable forever, and nothing reports it. |
| **Challenge key** | An opaque random `state` handle | Keying the store by the challenge itself lets anyone who observed one options payload probe for it. |
| **Ceremony binding** | Enforced | A registration challenge cannot be redeemed at the login endpoint. |
| **Origins** | Exact-match allow-list | No wildcards, no regex, no "ends with". The request's own `Origin` header is never used to derive the expected value — that is checking the attacker's claim against itself. |
| **Subdomains** | **Off** | `*.example.com` is opt-in and reviewed. |
| **RP ID** | Explicit config, validated at construction | Never taken from the request. An attacker-supplied RP ID mints credentials for a domain you do not control. |
| **Credential-ID uniqueness** | **Unique index**, plus an app check | The app check races; the index does not. Rejected across **all** users — re-pointing an existing credential ID at a new account is account takeover. |
| **`excludeCredentials`** | Every credential the user holds | The authenticator refuses the duplicate before the network round-trip. |
| **User handle** | 32 random bytes, minted lazily | **Never the primary key, never the email.** Every authenticator the user enrols stores a copy, so a sequential internal ID leaks to every device. |
| **User verification** | `preferred` | Set `required` when passkeys are the sole factor. The returned UV flag is enforced by the library. |
| **Resident key** | `preferred` | `required` consumes a scarce storage slot on hardware keys. |
| **Attestation** | `none` | See "Not in scope". |
| **Counter policy** | `reject` | See below. |
| **Transport** | POST, CSRF-protected, `Cache-Control: no-store` | The package does not exempt itself from CSRF. |
| **Storage encoding** | base64url **text**, not binary blobs | Mirroring across two runtimes and three databases with binary columns is where encoding bugs live. |

### The signature counter, specifically

The counter is a monotonic per-credential value that some authenticators
increment on each assertion. Its only purpose is **clone detection**: two
devices holding the same private key eventually produce a counter that goes
backwards.

- **Both counters zero → accepted.** Most synced passkey providers (iCloud
  Keychain, Google Password Manager) do not implement counters and always send
  0. A strict `new > stored` rule rejects the majority of real passkeys in the
  world. This is `web-auth`'s own behaviour and we do not tighten it.
- **Otherwise the new counter must be strictly greater.** Equal counts as a
  regression.
- **On regression the default policy is `reject`:** the login fails **and** the
  credential is stamped with `cloned_at` and a `PasskeyCloneDetected` event.
  Failing the login without recording it loses the signal forever — the next
  attempt from the real device advances the counter and the evidence is gone.
- **The new counter is persisted on every successful assertion, including when
  it is 0.** Not persisting it is the most common silent defeat of the whole
  mechanism: the stored value never advances, so every comparison is against 0
  and the check can never fire.
- `counter_policy` accepts `reject` (default), `log-only` (login succeeds, the
  credential is still flagged), and `ignore` — **`ignore` disables clone
  detection**, in those words, because an option named "ignore" reads as
  harmless.

### Errors and what they do and do not reveal

**Three codes are true internally and redacted on the wire.** Each one answers a
question about a credential this server holds, for a caller who has not
authenticated:

| Internal code | What it would reveal | On the wire |
|---|---|---|
| `unknown_credential` | "no such credential here" | `verification_failed` |
| `user_handle_mismatch` | "it exists, but not for this account" | `verification_failed` |
| `counter_regressed` | "it exists and we think it was cloned" | `verification_failed` |

All four share one status (401) and one message, so there is nothing left to
compare. Matching messages alone would not have been enough: `code` is the field
a client branches on, and a distinct code is just as good an oracle as a
distinct message.

`PasskeyException::$errorCode` keeps the **precise** value, so your logs,
listeners and metrics still see the real answer — a clone detection still stamps
`cloned_at` and still fires `PasskeyCloneDetected`. Only `toArray()` redacts.
Tell the user about a suspected clone through a channel that has actually
identified them; a login error is readable by a stranger.

The upstream library message — which names the failed check — is kept as the
exception's `previous` for your logs and never crosses the wire.

One honest caveat:
- Only `counter_regressed` and `user_handle_mismatch` are mapped from specific
  library exceptions. Wrong origin, wrong RP ID hash, missing user presence,
  missing user verification and a bad signature all collapse to
  `verification_failed` on this backend. The Node twin can distinguish some of
  these; this one deliberately does not.

### User enumeration

`POST /passkeys/login/options` with an unknown email returns **200 with an empty
`allowCredentials`**, never a 404 — a 404 there is a free enumeration endpoint.
A known user with no passkeys yet produces an identical response.

**The timing difference is not closed.** A real lookup happens either way, and
we have not measured the delta. If timing-based enumeration is in your threat
model, the discoverable flow — which takes no username at all, and is the
default — has nothing to enumerate.

---

## Wire contract

Both backends emit these payloads, byte for byte, for the same inputs. That is
the whole reason the pair exists: one React surface, either backend.

The options payloads are the W3C `…JSON` shapes — base64url `challenge`,
`user.id` and descriptor `id` fields — i.e. exactly what
`@simplewebauthn/browser` accepts without transformation.
`FancyPasskeys\Support\WireFormat` normalises `web-auth`'s serializer output to
match: it adds `authenticatorSelection.requireResidentKey`,
`extensions.credProps`, and an empty `hints` list, which are the three places
the two libraries differ.

`PasskeySummaryJSON` — the only credential shape that crosses the wire. Note
what is absent: the public key and the sign counter.

```json
{ "id": "base64url", "name": "MacBook Touch ID", "createdAt": "ISO-8601",
  "lastUsedAt": "ISO-8601|null", "transports": ["internal", "hybrid"],
  "backedUp": true, "aaguid": "uuid", "clonedAt": null }
```

`PasskeyErrorCode` (shared, closed set):
`challenge_expired` · `challenge_not_found` · `challenge_type_mismatch` ·
`origin_not_allowed` · `rp_id_mismatch` · `unknown_credential` ·
`credential_already_registered` · `counter_regressed` ·
`user_verification_required` · `user_handle_mismatch` · `verification_failed` ·
`invalid_response` · `not_supported`

`tests/WireParityTest.php` asserts this package's output against fixtures in
`tests/fixtures/wire/`, generated from the real `@simplewebauthn/server`; the
Node repo asserts against the same files. Change a wire shape here and you
change it there, in the same session, or the pair quietly stops being a pair.

---

## Not in scope for v1

Each of these is a real feature. Shipping a gesture at one is worse than not
shipping it.

- **Attestation trust decisions / FIDO MDS.** `attestation: 'none'` is the
  default and the only fully-supported mode. `direct` can be requested and the
  statement **is parsed and stored** — but **no trust decision is made from
  it**, now or anywhere in this package. Meaningful attestation verification
  needs the FIDO Metadata Service, certificate-chain validation and a revocation
  story; half-doing it produces a system that *looks* like it verifies device
  provenance and does not.
- **Enterprise attestation**, and any authenticator allow/deny list by AAGUID.
- **Passkey-only signup.** Creating an account from a registration ceremony with
  no prior user needs a provisioning policy, email verification and an
  anti-abuse story that belong to the app. Enrollment here happens on an
  already-authenticated user.
- **Account recovery.** If an app makes passkeys the sole factor and a user
  loses every device, recovery is application policy. Fortify's recovery codes
  remain the suggested path; we do not invent a second one.
- **Conditional create** (silent enrollment during a password login). The
  browser API exists; the UX and consent question is not settled, so it is not
  wired.
- **Multi-tenant / per-request RP IDs.** One RP ID per app instance.
- **Non-Laravel framework bridges.** The core is framework-free and usable
  directly; only Laravel gets a first-class bridge.
- **Cross-device linking specifics.** The browser handles hybrid transport; we
  expose the `transports` hints and nothing more.

---

## Tests

```bash
composer install
vendor/bin/pest
```

**Failure paths come first.** Auth code with only a happy-path test is untested
code — the happy path is what an attacker never uses. Covered: replayed
challenge (both ceremonies), expired challenge, ceremony-type mismatch in both
directions, disallowed origin, disallowed subdomain, unknown credential,
cross-user credential reuse, same-user reuse, user-handle mismatch, malformed
response, and the full counter rule.

None of these needs a real authenticator, and that is the design being
observable rather than a convenience: every one of those checks fires *before*
any signature is verified, so a response that merely parses is enough to reach
it. If one of them ever starts needing a valid signature, the ordering has been
inverted and the anti-replay property is gone.

---

## License

MIT.
