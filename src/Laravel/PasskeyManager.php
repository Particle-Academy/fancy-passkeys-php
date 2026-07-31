<?php

declare(strict_types=1);

namespace FancyPasskeys\Laravel;

use FancyPasskeys\PasskeyServer;
use FancyPasskeys\PasskeyUser;
use FancyPasskeys\StoredCredential;

/**
 * The `Passkeys` facade's target: the framework-free server plus the handful of
 * things that only make sense inside a Laravel app.
 *
 * Not final: rebinding a subclass in the container is the supported way to
 * change what the four controllers do without forking them.
 */
readonly class PasskeyManager
{
    public function __construct(private PasskeyServer $server)
    {
    }

    public function server(): PasskeyServer
    {
        return $this->server;
    }

    /** @return array{state: string, publicKey: array<string, mixed>} */
    public function startRegistration(PasskeyUser $user): array
    {
        return $this->server->startRegistration($user);
    }

    /**
     * @param  array<string, mixed>|string  $response
     * @return array{credential: StoredCredential, summary: array<string, mixed>}
     */
    public function finishRegistration(string $state, array|string $response, ?string $name = null): array
    {
        return $this->server->finishRegistration($state, $response, $name);
    }

    /** @return array{state: string, publicKey: array<string, mixed>} */
    public function startAuthentication(?string $userHandle = null): array
    {
        return $this->server->startAuthentication($userHandle);
    }

    /**
     * @param  array<string, mixed>|string  $response
     * @return array{credential: StoredCredential, summary: array<string, mixed>, userHandle: string}
     */
    public function finishAuthentication(string $state, array|string $response): array
    {
        return $this->server->finishAuthentication($state, $response);
    }

    /** @return list<array<string, mixed>> */
    public function listPasskeys(string $userHandle): array
    {
        return $this->server->listPasskeys($userHandle);
    }

    /**
     * The guard passkey login authenticates on.
     *
     * Resolved at runtime rather than in the config file, because a config file
     * cannot rely on another config file having been loaded yet.
     */
    public function guard(): string
    {
        $configured = config('passkeys.guard');

        if (is_string($configured) && $configured !== '') {
            return $configured;
        }

        /** @var string $guard */
        $guard = config('fortify.guard', 'web');

        return $guard;
    }

    /**
     * Whether this credential's ceremony was strong enough to stand in for a
     * second factor: the authenticator proved possession *and* verified the
     * user with a biometric or PIN.
     *
     * This reports the signal and stops. It deliberately does not act on it —
     * deciding that a UV passkey may skip a 2FA challenge the app configured is
     * the app's call, and the package's default is that it does not.
     */
    public function satisfiesTwoFactor(StoredCredential $credential): bool
    {
        return $this->server->policy->userVerification === 'required'
            && $credential->uvInitialized === true;
    }
}
