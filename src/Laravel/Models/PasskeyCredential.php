<?php

declare(strict_types=1);

namespace FancyPasskeys\Laravel\Models;

use FancyPasskeys\StoredCredential;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * @property int $id
 * @property int $user_id
 * @property string $credential_id
 * @property string $public_key
 * @property string $user_handle
 * @property int $sign_count
 * @property array<int, string>|null $transports
 * @property string|null $aaguid
 * @property bool|null $backed_up
 * @property bool|null $backup_eligible
 * @property bool|null $uv_initialized
 * @property string|null $attestation_format
 * @property string|null $name
 * @property \Illuminate\Support\Carbon|null $last_used_at
 * @property \Illuminate\Support\Carbon|null $cloned_at
 * @property \Illuminate\Support\Carbon|null $created_at
 */
class PasskeyCredential extends Model
{
    protected $guarded = [];

    protected $hidden = [
        // A management UI never needs these, and shipping them to the browser
        // is a gift to anyone who gets a read of the page.
        'public_key',
        'user_handle',
        'sign_count',
    ];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'transports' => 'array',
            'sign_count' => 'integer',
            'backed_up' => 'boolean',
            'backup_eligible' => 'boolean',
            'uv_initialized' => 'boolean',
            'last_used_at' => 'datetime',
            'cloned_at' => 'datetime',
        ];
    }

    public function getTable(): string
    {
        return $this->table ?? (string) config('passkeys.table', 'passkey_credentials');
    }

    /** @return BelongsTo<Model, $this> */
    public function user(): BelongsTo
    {
        /** @var class-string<Model> $model */
        $model = config('passkeys.users.model') ?? self::defaultUserModel();

        return $this->belongsTo($model);
    }

    public function toStoredCredential(): StoredCredential
    {
        return new StoredCredential(
            id: $this->credential_id,
            publicKey: $this->public_key,
            userHandle: $this->user_handle,
            signCount: (int) $this->sign_count,
            transports: array_values($this->transports ?? []),
            aaguid: $this->aaguid,
            backedUp: $this->backed_up,
            backupEligible: $this->backup_eligible,
            uvInitialized: $this->uv_initialized,
            attestationFormat: $this->attestation_format,
            name: $this->name,
            createdAt: self::iso($this->created_at) ?? '',
            lastUsedAt: self::iso($this->last_used_at),
            clonedAt: self::iso($this->cloned_at),
        );
    }

    private static function iso(mixed $value): ?string
    {
        if ($value === null) {
            return null;
        }

        /** @var \Illuminate\Support\Carbon $value */
        return $value->toIso8601ZuluString('millisecond');
    }

    /** @return class-string<Model> */
    private static function defaultUserModel(): string
    {
        /** @var class-string<Model> $model */
        $model = config('auth.providers.users.model', 'App\\Models\\User');

        return $model;
    }
}
