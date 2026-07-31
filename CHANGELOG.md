# Changelog

All notable changes to `particle-academy/fancy-passkeys` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Pre-1.0.** Breaking changes land in MINOR releases until 1.0.0. The version
> number is not yet a compatibility promise, so read this file before upgrading
> a minor.

## [Unreleased]

### Added

- Initial implementation. **Not published** — nothing is tagged and Packagist
  has no release for this yet.
- `PasskeyServer` — a framework-free server for both WebAuthn ceremonies:
  `startRegistration()` / `finishRegistration()` / `startAuthentication()` /
  `finishAuthentication()`. Wraps `web-auth/webauthn-lib` ^5.3; implements no
  cryptography of its own.
- `ChallengeStore` and `CredentialStore` interfaces, plus in-memory
  implementations for tests.
- `PasskeyException` carrying a closed `PasskeyErrorCode` set, identical to the
  Node twin's, so both backends return the same error body.
- `Support\WireFormat` — normalises `web-auth`'s serializer output into the
  shared wire shape the Node twin emits (`requireResidentKey`,
  `extensions.credProps`, an empty `hints` list). This is the one place PHP is
  made to agree with Node, and `tests/WireParityTest.php` holds it to fixtures
  generated from the real `@simplewebauthn/server`.
- `Support\CounterCheck` — the signature-counter rule as a named, tested
  function, so `log-only` can report what `reject` would have rejected even
  though the non-default policies suppress the library's own check.
- Laravel bridge: service provider, config, two migrations, `PasskeyCredential`
  model, `HasPasskeys` trait, `EloquentCredentialStore`, `CacheChallengeStore`,
  four routes, a `PasskeyManager` (incl. `satisfiesTwoFactor()`), and a
  `Passkeys` facade.
- `PasskeyRegistered`, `PasskeyAuthenticated` and `PasskeyCloneDetected` events.
- Fortify compatibility — login authenticates on `config('fortify.guard')` and
  fires `Illuminate\Auth\Events\Login`, so anything already listening on
  Fortify's login behaves identically. Fortify's own routes are untouched.

### Security

- Challenges are 32 CSPRNG bytes, single-use, and **consumed before
  verification** — `ChallengeStore::pull()` deletes as it reads, so a replayed
  response fails at "no such challenge" no matter how valid its signature is.
- Challenges are bound to their ceremony type; a registration challenge cannot
  be redeemed at the authentication endpoint.
- Origins are an exact-match allow-list with subdomain matching off by default.
  The request's own `Origin` header is never used to derive the expected value,
  and the RP ID is never taken from the request. A RP ID that is not a suffix
  of the configured origins throws at construction, not on the first login.
- The migration puts a **unique index** on `credential_id`. An application-level
  check races; the index does not.
- Signature-counter regression is rejected by default and stamps `cloned_at`,
  because the counter is a one-shot clone detector and a login that merely
  fails discards the signal.
- User handles are 32 random bytes minted per user, never the primary key —
  a user handle is stored by every authenticator the user enrolls.
- `unknown_credential` and `verification_failed` return the same status and the
  same message. The upstream library message — which names the failed check —
  is kept only as the exception's `previous`, for logs, and never crosses the
  wire.
- `POST /passkeys/login/options` answers 200 with an empty `allowCredentials`
  for an unknown email rather than 404. The README is explicit that the timing
  difference is not closed.
- All four routes are POST, CSRF-protected (the package does not exempt itself),
  and answer `Cache-Control: no-store`.
