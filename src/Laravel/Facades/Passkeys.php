<?php

declare(strict_types=1);

namespace FancyPasskeys\Laravel\Facades;

use FancyPasskeys\Laravel\PasskeyManager;
use Illuminate\Support\Facades\Facade;

/**
 * @method static \FancyPasskeys\PasskeyServer server()
 * @method static array{state: string, publicKey: array<string, mixed>} startRegistration(\FancyPasskeys\PasskeyUser $user)
 * @method static array{credential: \FancyPasskeys\StoredCredential, summary: array<string, mixed>} finishRegistration(string $state, array|string $response, ?string $name = null)
 * @method static array{state: string, publicKey: array<string, mixed>} startAuthentication(?string $userHandle = null)
 * @method static array{credential: \FancyPasskeys\StoredCredential, summary: array<string, mixed>, userHandle: string} finishAuthentication(string $state, array|string $response)
 * @method static list<array<string, mixed>> listPasskeys(string $userHandle)
 * @method static string guard()
 * @method static bool satisfiesTwoFactor(\FancyPasskeys\StoredCredential $credential)
 *
 * @see PasskeyManager
 */
final class Passkeys extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return PasskeyManager::class;
    }
}
