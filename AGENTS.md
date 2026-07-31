# AGENTS.md — fancy-passkeys-php

Passkey (WebAuthn) login for PHP. `CLAUDE.md` points here. Read the envelope's
`AGENTS.md` too, and `.ai/plans/fancy-passkeys.md` — that plan is the wire
contract this package and its Node twin are both held to.

## The rule that shapes this repo

**We do not implement WebAuthn cryptography, and we never will.**

CBOR decoding, COSE key parsing, ASN.1, attestation chains, RP-ID hashing,
`clientDataJSON` canonicalisation — this is the class of code whose bugs are
silent and total. A subtle mistake does not throw; it accepts a signature it
should have rejected, forever, for everyone, and the tests pass. So
`web-auth/webauthn-lib` does all of it and this package does none of it.

What this package owns is precisely what that library deliberately leaves to
the caller, and what almost every hand-rolled integration gets wrong:

1. **Issuing, storing, expiring, and single-using the challenge.**
2. **Persisting the credential**, and enforcing credential-ID uniqueness.
3. **Persisting the counter** after every successful assertion.
4. **Normalising errors** into a closed, wire-safe set.

If a change to this repo would put a crypto primitive in `src/`, the change is
wrong. Fix the wrapper, or fix it upstream.

## Targeting webauthn-lib v5 specifically

v5 is a large API break from v4 and most tutorials online are still v4. The
differences that matter here:

- The validators take **exactly one constructor argument**, a
  `CeremonyStepManager` built by `CeremonyStepManagerFactory`
  (`creationCeremony()` for registration, `requestCeremony()` for login). v4's
  repository + token-binding + extension-checker constructor is gone.
- Serialization goes through `WebauthnSerializerFactory` (Symfony Serializer).
  Options must be serialized with `AbstractObjectNormalizer::SKIP_NULL_VALUES
  => true` — without it you emit nulls the browser rejects.
- **`PublicKeyCredentialSource` is deprecated since 5.3.** Store and pass
  `Webauthn\CredentialRecord`. Passing the old class triggers a deprecation and
  it disappears in 6.0.
- **`PublicKeyCredentialSourceRepository` no longer exists in the library.**
  Credential lookup is our job — that is `CredentialStore`.
- `PublicKeyCredentialUserEntity::create()` takes `(name, id, displayName)`.
  Name first, id second. Getting this backwards produces a working ceremony
  with a garbage display name.
- `pubKeyCredParams` is **not** auto-populated when empty. Pass it explicitly
  or the browser has no algorithm to negotiate.
- `check()` takes a **host string** (`example.com`), not a full origin.

## The three things a reviewer should check first

### 1. The challenge is pulled BEFORE it is verified

```php
$record = $this->challenges->pull($handle);   // reads AND deletes
if ($record === null) {
    throw PasskeyException::challengeNotFound();
}
// ...only now do we verify
```

Inverted — verify first, delete after — a replayed response with a valid
signature succeeds on every retry, and nothing anywhere reports it. The
ordering is the entire anti-replay mechanism, and it is asserted in
`tests/ChallengeStoreTest.php` and `tests/CeremonyFailureTest.php`.

### 2. The updated `CredentialRecord` is persisted

`AuthenticatorAssertionResponseValidator::check()` **returns** a record with the
counter already advanced — it writes nothing. Dropping the return value is the
most common way the clone detector is silently defeated: the stored counter
never advances, so every comparison is against 0 and the check can never fire.

Related, and load-bearing: **both counters being 0 is accepted.** Most synced
passkey providers (iCloud Keychain, Google Password Manager) do not implement
counters and always send 0. This is `web-auth`'s own `CheckCounter` behaviour
and we do not tighten it.

### 3. Config is validated at construction, not at login

An RP ID that is not a suffix of the configured origins, or an origin list that
is empty, throws from `RelyingParty`'s constructor. Deferred, it surfaces as
every login failing in production with an opaque message. `RelyingPartyTest`
covers it.

## Laravel bridge: augment Fortify, never replace it

The starter kit and showcase run Fortify with Inertia views. Password login,
registration, reset, and 2FA must keep working untouched — passkeys are a
parallel path to the same session, not a fork of the auth stack.

- Log in via `StatefulGuard::login()` on **`config('fortify.guard')`**, then
  regenerate the session and fire `Illuminate\Auth\Events\Login`. Anything
  already listening on Fortify's login (fun-lab, heuristics, audit) must not be
  able to tell the difference.
- Reuse Fortify's `login` rate limiter when it is registered. An unthrottled
  passkey endpoint beside a throttled password endpoint is a bypass.
- Never modify or re-register a Fortify route.
- Passkey login does **not** skip a configured 2FA challenge by default.
  Deciding a UV passkey is sufficient is the app's call; `satisfiesTwoFactor()`
  exposes the signal without making the decision.

## Wire parity with the Node twin

`@particle-academy/fancy-passkeys` (Node) must emit an **equal** payload —
deep-equal once parsed, since key order is not part of the contract.
That is the whole reason the pair exists: one React surface, either backend.
`tests/WireParityTest.php` asserts against fixtures in `tests/fixtures/wire/`,
and the Node repo asserts against the same files. If you change a wire shape
here, change it there in the same session, or the pair quietly stops being a
pair.

## Commands

```bash
composer install
vendor/bin/pest
```

## Conventions

- **Tests cover failure paths first.** Auth code with only a happy-path test is
  untested code: the happy path is what an attacker never uses. Required
  coverage: replayed challenge, expired challenge, ceremony-type mismatch,
  wrong origin, counter regression, unknown credential, cross-user credential
  reuse.
- **No error message leaks whether a credential exists.** `unknown_credential`
  and a bad signature must be indistinguishable to the client.
- The framework-free core in `src/` must not import `Illuminate\*`. Everything
  Laravel lives under `src/Laravel/`, and `illuminate/support` is a `suggest`,
  never a `require`.
- `CHANGELOG.md` is updated in the SAME commit as the change.
