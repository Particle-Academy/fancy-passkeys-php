# Using particle-academy/fancy-passkeys (PHP) — guide for agents

How an agent installs and uses this package in a consumer app. What the package
is, is in [README.md](./README.md). Notes for working ON this repo's code are in
[CONTRIBUTING.md](./CONTRIBUTING.md).

## Install

```bash
composer require particle-academy/fancy-passkeys
```

- **PHP:** `^8.4`. The repo is `fancy-passkeys-php`; the Composer name is
  `particle-academy/fancy-passkeys`. The Node twin is the npm package
  `@particle-academy/fancy-passkeys`.
- Laravel and Fortify are suggests, not requirements; the core runs without
  them.
- **Laravel:**

  ```bash
  php artisan vendor:publish --tag=passkeys-config
  php artisan vendor:publish --tag=passkeys-migrations   # optional; they auto-load
  php artisan migrate
  ```

  ```dotenv
  PASSKEYS_RP_ID=example.com
  PASSKEYS_RP_NAME="Example App"
  PASSKEYS_ORIGINS=https://example.com,https://www.example.com
  ```

  Add `FancyPasskeys\Laravel\Concerns\HasPasskeys` to the `User` model.
- **Browser side:** `@particle-academy/fancy-passkeys-ui` (its React-free
  `/client` subpath runs the ceremony).

## Find it on the Fancy MCP server

The catalog server is `https://ui.particle.academy/mcp` (streamable HTTP, no API
key; MCP id `fancy-ui`). This package's registry entry is `fancy-passkeys`. As a
server-side package it is found with `search-backend-packages` (stack `php`);
`install-instructions` gives the exact install commands. The UI is
`@particle-academy/fancy-passkeys-ui` (entries `passkey-sign-in`,
`passkey-manager`, `passkey-status`).

## API essentials

- **Laravel routes** (prefix `passkeys`, middleware `web`, registered
  automatically): `POST /passkeys/register/options` and `POST /passkeys/register`
  (auth), `POST /passkeys/login/options` and `POST /passkeys/login` (guest).
  Errors answer `{ "error": { "code", "message" } }`.
- **Trait `HasPasskeys`:** `passkeys()` relation and `passkeyUserHandle()`
  (mints 32 random bytes on first use).
- **Events:** `PasskeyRegistered`, `PasskeyAuthenticated`,
  `PasskeyCloneDetected`; Laravel's own `Login` fires as for a password login.
- **`Passkeys::satisfiesTwoFactor($credential)`** reports whether the ceremony
  could stand in for 2FA; acting on it is the app's call.
- **Framework-free:** `new PasskeyServer(new RelyingParty($id, $name, $origins),
  PasskeyPolicy::default(), $challengeStore, $credentialStore)` with
  `startRegistration(new PasskeyUser(...))`, `finishRegistration`,
  `startAuthentication()`, `finishAuthentication`.
- **Stores:** implement `ChallengeStore` (`put`, `pull`) and `CredentialStore`;
  or use `Support\InMemoryChallengeStore` / `Support\InMemoryCredentialStore`
  (one process) and `Laravel\CacheChallengeStore` /
  `Laravel\EloquentCredentialStore`.
- Login certificates are optional; see the README.

## Traps

- **The RP ID must be the host, or a registrable suffix, of every origin.** In
  Laravel a bad value surfaces on the first passkey request (a 500 with the
  reason in the log), not at boot. To fail fast in a deploy step:
  `php artisan tinker --execute="app(FancyPasskeys\RelyingParty::class);"`.
- **Local development:** `PASSKEYS_RP_ID=localhost` and
  `PASSKEYS_ORIGINS=http://localhost:5173`. `http://` works only on `localhost`
  and `*.localhost`; IP hosts such as `127.0.0.1` are refused.
- **The routes are CSRF-protected**, deliberately; send the token.
- **It augments Fortify and never touches a Fortify route.** Login uses
  `config('passkeys.guard')` (default: Fortify's guard), reuses Fortify's `login`
  rate limiter when registered, and does not skip a configured 2FA challenge.
- **Do not dispatch `Login` yourself after a passkey login**; it already fired,
  and listeners would double-count.
- **`ChallengeStore::pull()` must delete as it reads** and treat an expired
  record as absent. That is the anti-replay mechanism.
- **`CredentialStore::save()` throws on a duplicate id**; keep the unique index
  on `credential_id`.
- **Three error codes are redacted on the wire** to `verification_failed`
  (`unknown_credential`, `user_handle_mismatch`, `counter_regressed`).
  `PasskeyException::$errorCode` keeps the precise value for logs.
- Attestation trust, passkey-only signup, account recovery and per-request RP
  IDs are out of scope.
