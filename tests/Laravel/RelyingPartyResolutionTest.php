<?php

declare(strict_types=1);

use FancyPasskeys\Laravel\PasskeysServiceProvider;
use FancyPasskeys\PasskeyServer;
use FancyPasskeys\RelyingParty;

/*
 * What the README promises about a bad relying party in Laravel: the provider
 * registers and boots with it, and it is refused when the passkey server is
 * first resolved (the first passkey request), never with ceremony options.
 *
 * Not at boot on purpose: the default config is derived from APP_URL, so an
 * app on http://myapp.test that has not configured passkeys yet would
 * otherwise fail every page and every artisan command, including composer's
 * package:discover. The README said "throws at boot" until 2026-11-13; the lab
 * benchmark found it throws on first use, which is the behaviour pinned here.
 */

function useRelyingParty(array $rp): void
{
    config()->set('passkeys.rp', $rp + ['name' => 'Fancy Passkeys Test', 'allow_subdomains' => false]);
    app()->forgetInstance(RelyingParty::class);
    app()->forgetInstance(PasskeyServer::class);
}

it('boots with an IP-literal relying party and refuses it on first use', function () {
    useRelyingParty(['id' => '127.0.0.1', 'origins' => ['http://127.0.0.1:8000']]);

    $provider = new PasskeysServiceProvider(app());
    $provider->register();
    $provider->boot();

    expect(fn () => app(RelyingParty::class))->toThrow(InvalidArgumentException::class);
});

it('answers the first passkey request with a 500 and issues no options', function () {
    useRelyingParty(['id' => 'example.com', 'origins' => ['http://example.com']]);

    $response = $this->postJson('/passkeys/login/options');

    expect($response->status())->toBe(500);
    expect($response->json('publicKey'))->toBeNull();
});
