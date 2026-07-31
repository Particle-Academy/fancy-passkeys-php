<?php

declare(strict_types=1);

namespace FancyPasskeys\Laravel\Concerns;

use FancyPasskeys\Laravel\Models\PasskeyCredential;
use FancyPasskeys\Support\Base64Url;
use Illuminate\Database\Eloquent\Relations\HasMany;

/**
 * Add to the authenticatable model. Fortify's user contract is untouched.
 *
 * @property string|null $passkey_user_handle
 */
trait HasPasskeys
{
    /** @return HasMany<PasskeyCredential, $this> */
    public function passkeys(): HasMany
    {
        return $this->hasMany(PasskeyCredential::class);
    }

    /**
     * The WebAuthn user handle, minted on first use and persisted.
     *
     * **Never the primary key, never the email.** The handle is transmitted to
     * and stored by every authenticator this user ever enrols, so a sequential
     * database ID here hands an enumerable internal identifier to every device
     * (and to anyone who can read one). 32 bytes from the CSPRNG costs nothing
     * and leaks nothing.
     */
    public function passkeyUserHandle(): string
    {
        $handle = $this->passkey_user_handle;

        if (is_string($handle) && $handle !== '') {
            return $handle;
        }

        $handle = Base64Url::encode(random_bytes(32));

        $this->forceFill(['passkey_user_handle' => $handle])->save();

        return $handle;
    }
}
