# Changelog

All notable changes to `particle-academy/fancy-passkeys` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Pre-1.0.** Breaking changes land in MINOR releases until 1.0.0. The version
> number is not yet a compatibility promise, so read this file before upgrading
> a minor.

## [Unreleased]

### Added

- **`$origins` may be a `Closure`**, called on every verification and validated
  each time with the same rules as a static list, including the localhost and
  IP-literal rules. `RelyingParty::setOrigins()` replaces the list or Closure (a
  refused list leaves the old one in place); `hasDynamicOrigins()` tells the two
  apart. Mirrors the Node twin's `OriginResolver`. Built for desktop apps whose
  local server port is picked at launch; the README documents the single-user
  desktop shape.
- **Optional login certificates.** `new PasskeyServer(..., certificates: new
  LoginCertificates(...))` (off by default) issues a canonical record of each
  successful sign-in and enrollment, with app-supplied claims, and a token
  `fplc_v1_<sha256 hex>` of its canonical bytes. `LoginCertificate::issue()`,
  `::token()`, `::verify()` and `::isSensitiveKey()` are public;
  `Support\CanonicalJson` is a copy of change-council's canonical form, and
  `tests/fixtures/login-certificate/vectors.json` is shared with the Node twin,
  so tokens agree across backends. Known-sensitive claim keys are stripped and
  reported. The package stores nothing.
- Laravel: `passkeys.certificates` config (`PASSKEYS_CERTIFICATES`, default
  false), request claims by default, and a `PasskeyCertificateIssued` event as
  the storage hook.
- `finishRegistration()` takes an optional fourth argument and
  `finishAuthentication()` an optional third, the certificate claims; both
  results carry a `certificate` key (`null` unless certificates are on).
  Additive: `PasskeyManager`'s signatures are unchanged, so subclasses keep
  working.

### Changed

- **`RelyingParty` is no longer a `readonly` class.** `id`, `name` and
  `allowSubdomains` are still readonly properties; only the origins are
  mutable, through `setOrigins()`. **Consumer action:** none, unless you
  extended it (it is `final`, so you did not).
- **A policy algorithm that `web-auth/webauthn-lib` cannot verify is refused when
  `PasskeyServer` is constructed.** Supported: -8, -7, -35, -36, -257, -258,
  -259, -37, -38, -39. **Consumer action:** only if you configured another
  identifier, which could enroll credentials that then never signed in. The
  default list is unchanged.
- **BREAKING (wire): a wrong-origin response now answers `origin_not_allowed`
  (400), not `verification_failed` (401)**, for sign-in and registration alike.
  This is what the Node twin has always answered; the `passkeys` lab benchmark
  found the two disagreeing on the same assertion. The origin is now decided
  BEFORE the credential is looked up, using web-auth's own `CheckAllowedOrigins`
  step, so the answer is the same whether or not the credential exists and is
  not an existence oracle. The shared fixture `tests/fixtures/errors/codes.json`
  (byte-identical in both repos) pins every code's status and wire code and
  these named failures. **Consumer action:** only if your client branches on
  `verification_failed` or a 401 to detect a wrong origin; `fancy-passkeys-ui`
  already handles `origin_not_allowed`.

### Fixed

- **A stored credential with no AAGUID no longer crashes sign-in.** The record
  handed to the library was built with Symfony's `Uuid::NIL`, a protected
  constant, so a credential whose `aaguid` was null threw an `Error` (a 500)
  before any verification ran. **Consumer action:** none.
- **README: a bad relying party is refused on the first passkey request, not at
  boot** as it said. In Laravel the `RelyingParty` singleton is lazy, so a bad
  `passkeys.rp` answers that request with a 500 (the reason is in the log) and
  never issues ceremony options. It stays lazy on purpose: the default config
  is derived from `APP_URL`, and failing at boot would take down every page and
  every artisan command (including `package:discover`) for an app on
  `http://myapp.test` that has not configured passkeys yet. The README shows a
  one-line deploy check for anyone who wants it to fail fast.

- **Ed25519 passkeys can sign in.** The default policy offers Ed25519 (-8)
  FIRST, and registration accepted it, but the signature check only had ES256
  and RS256 (`CeremonyStepManagerFactory`'s default). An authenticator that
  chose Ed25519 enrolled without complaint and then failed every sign-in with
  `verification_failed`. The signature check now has exactly the algorithms the
  policy offers. The Node twin was not affected. **Consumer action:** none;
  such credentials start working. Found by a new test suite that completes real
  ceremonies with a software authenticator (tests only).
- **`RelyingParty` now accepts `*.localhost` hosts over plain http.** A
  configuration such as RP ID `genie.localhost` with origin
  `http://genie.localhost:5678` threw at construction, although Chromium runs
  WebAuthn there without complaint. http is allowed for `localhost` and for any
  name whose LAST LABEL is exactly `localhost` (`foo.localhost`,
  `a.b.localhost`), at any port. `localhost.evil.com` and `evilocalhost` still
  need https. The RP ID / origin rule is unchanged: the RP ID must be the
  origin's host or a registrable suffix of it.
- A non-https, non-http scheme on a localhost host (`ftp://localhost`) is now
  refused; only http is relaxed.

### Security

- **SECURITY-RELEVANT — IP-address hosts are no longer accepted, including
  `127.0.0.1` and `[::1]`.** `RelyingParty` used to allow http on `127.0.0.1`
  and `[::1]`, and an RP ID equal to either. Chromium refuses an IP literal as
  an RP ID ("This is an invalid domain"), so such a configuration constructed
  cleanly and then failed every ceremony in the browser. Any IPv4 or IPv6
  literal is now refused at construction, as an RP ID and as an origin host,
  over http or https. IPv4 is detected by the URL standard's "ends in a number"
  rule, so short forms such as `127.1` are caught too. **Consumer action:** only
  if `PASSKEYS_RP_ID` / `PASSKEYS_ORIGINS` (or an `APP_URL` they default from)
  name an IP such as `http://127.0.0.1:8000`: switch to `localhost` or a
  `*.localhost` name. Those configurations never worked in a browser, so
  nothing that worked before stops working. The accepted and refused cases are
  a fixture table (`tests/fixtures/relying-party/origins.json`) shared with the
  Node twin.

## 0.2.1 — 2026-08-09

### Added

- **Cross-user credential reuse is now tested in the DISCOVERABLE flow too**,
  closing the last gap against the Node twin's coverage.

  The username-first flow was already covered: the wrapper compares the stored
  handle against the account the ceremony named. The discoverable flow takes a
  different path — there is no named account, so that comparison is skipped and
  the handle the authenticator reports is the only thing tying the credential to
  a user. Two cases now cover it: a reported handle that is not the stored one,
  and no reported handle at all.

  Both were already refused correctly, by `webauthn-lib`'s `CheckUserHandle` —
  this is test coverage, **not a fix, and no behaviour changed**. It is worth
  having because the check is invisible from this package: nothing in `src/`
  shows it happening, so nothing would have noticed it stop. Verified by
  mutation — handing the library a non-null expected handle (a plausible
  "tidy-up") makes the absent-handle case pass silently, and now fails the suite.


## 0.2.0 — 2026-08-07

### Changed

- **BREAKING — PHP 8.2 is no longer supported.** `require.php` moves from `^8.2` to `^8.4`.

  **What you must do:** on PHP 8.4 or newer, nothing. On 8.2, either upgrade PHP first or stay on the previous release — it keeps working and is unaffected by this.

- CI now tests PHP 8.4 only, instead of a matrix spanning versions this package no longer claims to support. A matrix that tests what the manifest forbids is worse than none — it reports green for a combination nobody can install.

### Why

These are the kit 0.5 platform floors. The suite was split across PHP 8.2 and 8.3 with the framework spanning 11–13, so no package could rely on anything newer than its weakest sibling. Every PHP package in the kit takes the same floors at once, so a consumer never has to resolve a mix.

Pre-1.0, so this lands in a MINOR. **No API changed, nothing was removed, nothing was renamed** — only what the package requires.


## 0.1.0 — 2026-08-01

**First published release.** Passkey (WebAuthn) login for Laravel — a thin wrapper over `web-auth/webauthn-lib` with **no cryptography of our own**. Augments Fortify rather than replacing it.

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
- **Three codes are true internally and redacted on the wire.**
  `unknown_credential`, `user_handle_mismatch`, and `counter_regressed` all
  reach the client as `verification_failed`, with the same message and the same
  401. Matching messages alone were not enough: `code` is the field a client
  branches on, so a distinct code is just as good a credential-existence oracle
  as a distinct message. `PasskeyException::$errorCode` keeps the precise value
  — clone detection still stamps `cloned_at` and still fires
  `PasskeyCloneDetected` — and only `toArray()` redacts.
- The upstream library message — which names the failed check — is kept only as
  the exception's `previous`, for logs, and never crosses the wire.
- `POST /passkeys/login/options` answers 200 with an empty `allowCredentials`
  for an unknown email rather than 404. The README is explicit that the timing
  difference is not closed.
- All four routes are POST, CSRF-protected (the package does not exempt itself),
  and answer `Cache-Control: no-store`.
