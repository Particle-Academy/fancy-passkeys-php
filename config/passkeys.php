<?php

declare(strict_types=1);

return [

    /*
    |--------------------------------------------------------------------------
    | Relying party
    |--------------------------------------------------------------------------
    |
    | Who you claim to be, and which origins may speak for you. Both are
    | validated when the server is constructed: an RP ID that is not the host of
    | (or a registrable suffix of) every configured origin throws immediately,
    | rather than failing every login in production with an opaque browser error.
    |
    | The origin list is an EXACT-MATCH allow-list. No wildcards, no regex. The
    | request's own Origin header is never consulted — checking the attacker's
    | claim against itself is not a check.
    |
    */

    'rp' => [
        'id' => env('PASSKEYS_RP_ID', parse_url((string) env('APP_URL', 'http://localhost'), PHP_URL_HOST) ?: 'localhost'),

        'name' => env('PASSKEYS_RP_NAME', env('APP_NAME', 'Laravel')),

        // Comma-separated. e.g. "https://example.com,https://www.example.com"
        'origins' => array_values(array_filter(array_map(
            'trim',
            explode(',', (string) env('PASSKEYS_ORIGINS', env('APP_URL', 'http://localhost')))
        ))),

        // "*.example.com". Off by default, and turning it on should be a
        // deliberate, reviewed decision.
        'allow_subdomains' => (bool) env('PASSKEYS_ALLOW_SUBDOMAINS', false),
    ],

    /*
    |--------------------------------------------------------------------------
    | Ceremony policy
    |--------------------------------------------------------------------------
    */

    'policy' => [
        // 'required' when passkeys are the sole factor, otherwise 'preferred'.
        'user_verification' => env('PASSKEYS_USER_VERIFICATION', 'preferred'),

        // 'required' consumes a storage slot on hardware keys, which have very
        // few. 'preferred' still gets discoverable credentials on every
        // platform authenticator that matters.
        'resident_key' => env('PASSKEYS_RESIDENT_KEY', 'preferred'),

        // 'direct' is accepted and the statement is stored, but NO trust
        // decision is made from it. See the README's "Not in scope" section.
        'attestation' => env('PASSKEYS_ATTESTATION', 'none'),

        'timeout_ms' => (int) env('PASSKEYS_TIMEOUT_MS', 60000),

        // Deliberately longer than the browser timeout above: a slow but
        // legitimate ceremony must not be punished.
        'challenge_ttl' => (int) env('PASSKEYS_CHALLENGE_TTL', 300),

        // COSE identifiers, most-preferred first: Ed25519, ES256, RS256.
        'algorithms' => [-8, -7, -257],

        // 'reject' (default) — a regressed signature counter fails the login and
        //                      stamps cloned_at.
        // 'log-only'         — the login succeeds; the credential is still flagged.
        // 'ignore'           — THIS DISABLES CLONE DETECTION. Nothing is recorded.
        'counter_policy' => env('PASSKEYS_COUNTER_POLICY', 'reject'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Routes
    |--------------------------------------------------------------------------
    |
    | Four POST endpoints in their own group. Fortify's routes are never
    | touched, re-registered, or replaced — passkeys are a parallel path to the
    | same session.
    |
    */

    'routes' => [
        'enabled' => true,

        'prefix' => env('PASSKEYS_ROUTE_PREFIX', 'passkeys'),

        // The package does NOT exempt itself from CSRF.
        'middleware' => ['web'],

        // Enrollment happens on an authenticated user.
        'auth_middleware' => ['auth'],

        // Fortify's 'login' limiter is reused when it is registered, so an
        // app's existing throttle covers the passkey path too. An unthrottled
        // passkey endpoint beside a throttled password endpoint is a bypass,
        // not a feature.
        'limiter' => env('PASSKEYS_RATE_LIMITER', null),
    ],

    /*
    |--------------------------------------------------------------------------
    | Guard
    |--------------------------------------------------------------------------
    |
    | Null means "whatever Fortify is configured to use" — resolved at runtime
    | from config('fortify.guard'), falling back to 'web'. Resolving it here
    | would depend on config file load order.
    |
    */

    'guard' => env('PASSKEYS_GUARD'),

    /*
    |--------------------------------------------------------------------------
    | Challenge cache
    |--------------------------------------------------------------------------
    |
    | Challenges are server-side, single-use, and short-lived. Null uses the
    | default cache store. Note that the 'array' driver is per-process and will
    | break the ceremony across workers.
    |
    */

    'cache' => [
        'store' => env('PASSKEYS_CACHE_STORE'),
        'prefix' => 'passkeys:challenge:',
    ],

    /*
    |--------------------------------------------------------------------------
    | Storage
    |--------------------------------------------------------------------------
    */

    'table' => 'passkey_credentials',

    'users' => [
        'table' => 'users',

        // Defaults to the provider model of the resolved guard.
        'model' => env('PASSKEYS_USER_MODEL'),
    ],

];
